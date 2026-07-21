#!/usr/bin/env python3
"""
GLPI Assets Inventory Exporter v3 - Pure Data Integrity Edition
Generates an assets_inventory.csv file from GLPI MariaDB database and/or
upserts assets into a PostgreSQL (Neon) database.
Maintains 100% integrity of raw database entries without transformation.

CSV Columns (28):
  type,hostname,ip,subnet_mask,mac,location,criticality,owner,source,status,
  os,osVersion,kernelVersion,architecture,ports,software,
  vendor,model,product_number,serial,firmware,network_zone,
  glpi_id,glpi_type,purchase_date,warranty_end,last_updated,ticket_count
"""

import csv
import json
import logging
import os
import re
import shutil
import stat
import sys
import time
from datetime import datetime, date
from pathlib import Path
from logging.handlers import RotatingFileHandler
import mysql.connector
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()

# ============================================================
# CONFIGURATION (from .env file)

def _parse_bool(val):
    """Parse a string as a boolean. Accepts 'true'/'false', '1'/'0', 'yes'/'no' (case-insensitive)."""
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    return s in ('true', '1', 'yes', 'y')

# --- GLPI (MySQL) connection ---
DB_CONFIG = {
    'host': os.getenv('DB_HOST', '172.17.0.1'),
    'port': int(os.getenv('DB_PORT', '3306')),
    'user': os.getenv('DB_USER', 'glpi'),
    'password': os.getenv('DB_PASSWORD', 'glpi'),
    'database': os.getenv('DB_NAME', 'glpi'),
}

# SSL connection parameters for remote GLPI databases
ssl_ca = os.getenv('DB_SSL_CA')
ssl_cert = os.getenv('DB_SSL_CERT')
ssl_key = os.getenv('DB_SSL_KEY')
ssl_verify_cert = os.getenv('DB_SSL_VERIFY_CERT')
ssl_verify_identity = os.getenv('DB_SSL_VERIFY_IDENTITY')
use_pure = os.getenv('DB_USE_PURE')

if ssl_ca:
    DB_CONFIG['ssl_ca'] = ssl_ca
if ssl_cert:
    DB_CONFIG['ssl_cert'] = ssl_cert
if ssl_key:
    DB_CONFIG['ssl_key'] = ssl_key
if ssl_verify_cert is not None:
    DB_CONFIG['ssl_verify_cert'] = _parse_bool(ssl_verify_cert)
if ssl_verify_identity is not None:
    DB_CONFIG['ssl_verify_identity'] = _parse_bool(ssl_verify_identity)
if use_pure is not None:
    DB_CONFIG['use_pure'] = _parse_bool(use_pure)

# --- Neon (PostgreSQL) connection ---
PG_DSN = os.getenv('PG_DSN', '')
PG_CONNECT_TIMEOUT = int(os.getenv('PG_CONNECT_TIMEOUT', '10'))

# --- Output mode ---
# 'csv' | 'postgresql' | 'both'
OUTPUT_MODE = os.getenv('OUTPUT_MODE', 'csv').strip().lower()

# Asset names to exclude (comma-separated in .env)
EXCLUDED_ASSETS_RAW = os.getenv('EXCLUDED_ASSETS', '')
EXCLUDED_ASSETS = [a.strip() for a in EXCLUDED_ASSETS_RAW.split(',') if a.strip()]

# Output settings (used when OUTPUT_MODE is 'csv' or 'both')
OUTPUT_FILE = os.getenv('OUTPUT_FILE', 'assets_inventory.csv')
BACKUP_COUNT = int(os.getenv('BACKUP_COUNT', '3'))
LOG_FILE = os.getenv('LOG_FILE', 'generate_inventory.log')
LOG_LEVEL_NAME = os.getenv('LOG_LEVEL', 'INFO')
LOG_LEVEL = getattr(logging, LOG_LEVEL_NAME.upper(), logging.INFO)

# DB retry settings
DB_RETRY_COUNT = int(os.getenv('DB_RETRY_COUNT', '3'))
DB_RETRY_DELAY = int(os.getenv('DB_RETRY_DELAY', '2'))  # seconds

# ============================================================
# OUTPUT DIRECTORY VALIDATION & SYMLINK RESOLUTION
# ============================================================
def map_criticality(raw_criticality):
    """Map GLPI criticality (if any) to allowed PG values; default to MEDIUM."""
    # If you don't have a criticality field, always return 'MEDIUM'
    return 'MEDIUM'

def map_status(raw_state):
    """Map GLPI state name to allowed PostgreSQL status."""
    mapping = {
        'In use': 'ACTIVE',
        'Under repair': 'INACTIVE',
        'In stock': 'INACTIVE',
        'Retired': 'RETIRED',
        # add others as needed
    }
    # If raw_state is None or empty, default to ACTIVE
    if not raw_state:
        return 'ACTIVE'
    return mapping.get(raw_state, 'ACTIVE')
def resolve_and_validate_output(path_str):
    """
    Resolve symlinks in the given path string and validate the output directory.

    Returns the resolved absolute path string.
    Raises:
        FileNotFoundError  – if the parent directory does not exist
        PermissionError    – if the parent directory is not writable
        NotADirectoryError – if the parent is not a directory
    """
    path = Path(path_str)

    resolved_parent = path.parent.resolve()
    if not resolved_parent.exists():
        raise FileNotFoundError(
            f"Output directory does not exist: {resolved_parent}"
        )
    if not resolved_parent.is_dir():
        raise NotADirectoryError(
            f"Output path parent is not a directory: {resolved_parent}"
        )
    if not os.access(str(resolved_parent), os.W_OK):
        raise PermissionError(
            f"Output directory is not writable: {resolved_parent}"
        )

    resolved_path = resolved_parent / path.name
    if resolved_path.exists() or resolved_path.is_symlink():
        resolved_path = resolved_path.resolve()

    return str(resolved_path)


def set_secure_permissions(filepath):
    """Set file permissions to 0o600 (owner read/write only)."""
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        log.warning(f"Could not set permissions 0o600 on {filepath}: {e}")


# ============================================================
# CSV COLUMNS
# ============================================================

CSV_COLUMNS = [
    'type', 'hostname', 'ip', 'subnet_mask', 'mac', 'location', 'criticality',
    'owner', 'source', 'status', 'os', 'osVersion', 'kernelVersion',
    'software',
    'vendor', 'model', 'product_number', 'serial', 'firmware',
    'network_zone', 'glpi_id', 'glpi_type', 'purchase_date', 'warranty_end',
    'last_updated', 'ticket_count',
]

# ============================================================
# LOGGING SETUP
# ============================================================

def setup_logging():
    logger = logging.getLogger('glpi_inventory')
    logger.setLevel(LOG_LEVEL)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(LOG_LEVEL)
    console.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(console)

    return logger


def setup_file_logging(logger, log_file):
    """Add a RotatingFileHandler to the logger with the resolved log file path."""
    try:
        fh = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(fh)
    except (IOError, PermissionError) as e:
        logger.warning(f"Could not create log file {log_file}: {e}")
    return logger


log = setup_logging()

# ============================================================
# PASSTHROUGH INTEGRITY HELPERS
# ============================================================

def preserve_raw(row, key):
    """Safely fetch raw DB contents without parsing, formatting, or altering null values."""
    if row is None:
        return ''
    val = row.get(key)
    return '' if val is None else str(val)

def connect_db():
    for attempt in range(1, DB_RETRY_COUNT + 1):
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            log.info(f"Connected to GLPI database {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}")
            return conn
        except mysql.connector.Error as e:
            log.error(f"GLPI DB connection attempt {attempt}/{DB_RETRY_COUNT} failed: {e}")
            if attempt < DB_RETRY_COUNT:
                log.info(f"Retrying in {DB_RETRY_DELAY}s...")
                time.sleep(DB_RETRY_DELAY)
            else:
                log.critical("All GLPI database connection attempts failed. Exiting.")
                sys.exit(1)

def connect_pg():
    """Connect to the Neon (PostgreSQL) database using the DSN."""
    if not PG_DSN:
        log.error("PG_DSN is not set. Cannot connect to PostgreSQL database.")
        return None
    try:
        conn = psycopg2.connect(PG_DSN, connect_timeout=PG_CONNECT_TIMEOUT)
        log.info("Connected to Neon (PostgreSQL) database.")
        return conn
    except psycopg2.Error as e:
        log.error(f"Neon DB connection failed: {e}")
        return None

def extract_os_from_sysdescr(sysdescr):
    """Fallback parser for Network Equipment OS extraction."""
    if not sysdescr:
        return '', '', ''
    desc = str(sysdescr)
    desc_lower = desc.lower()

    if 'cisco ios' in desc_lower:
        m = re.search(r'version\s+(\S+)', desc, re.IGNORECASE)
        return 'Cisco IOS', (m.group(1) if m else ''), ''
    elif 'fortinet' in desc_lower or 'fortigate' in desc_lower:
        m = re.search(r'version\s+(\S+)', desc, re.IGNORECASE)
        return 'FortiOS', (m.group(1) if m else ''), ''
    elif 'aruba' in desc_lower:
        m = re.search(r'version\s+(\S+)', desc, re.IGNORECASE)
        return 'ArubaOS', (m.group(1) if m else ''), ''
    elif 'linux' in desc_lower:
        m = re.search(r'(\d+\.\d+\.\d+[^\s]*)', desc)
        return 'Linux', (m.group(1) if m else ''), ''

    return '', '', ''

def is_asset_excluded(hostname):
    return hostname in EXCLUDED_ASSETS

def atomic_csv_write(rows, columns, output_file, backup_count):
    temp_file = output_file + '.tmp'
    try:
        with open(temp_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)

        set_secure_permissions(temp_file)

        if os.path.exists(output_file):
            for i in range(backup_count - 1, 0, -1):
                src = f"{output_file}.{i}"
                dst = f"{output_file}.{i + 1}"
                if os.path.exists(src):
                    shutil.move(src, dst)
            shutil.move(output_file, output_file + '.1')

        shutil.move(temp_file, output_file)
    except (IOError, OSError, PermissionError) as e:
        log.error(f"Failed to write CSV: {e}")
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass
        raise

# ============================================================
# NEON (POSTGRESQL) UPSERT FUNCTIONS
# ============================================================

def classify_asset_type(glpi_type, device_type, os_name):
    """
    Classify a GLPI asset into one of: 'server', 'endpoint', 'network_device'.

    - glpi_type: 'Computer' or 'NetworkEquipment' from GLPI
    - device_type: the GLPI computer/network type name (e.g. 'Server', 'Desktop', 'Laptop')
    - os_name: the operating system name
    """
    if glpi_type == 'NetworkEquipment':
        return 'NetworkDeviceAsset'

    # For computers, use the device_type name to decide
    dt_lower = (device_type or '').lower()
    if 'server' in dt_lower:
        return 'ServerAsset'
    # If no explicit type, check OS
    os_lower = (os_name or '').lower()
    if any(kw in os_lower for kw in ('server', 'centos', 'rhel', 'debian', 'ubuntu server')):
        return 'ServerAsset'
    # Default to endpoint for workstations, laptops, desktops, etc.
    return 'EndpointAsset'


def upsert_asset(pg_conn, asset_data):
    """
    Upsert a single asset into the Neon database using ip_address as the unique key.
    """
    ip_address = asset_data.get('ip', '') or None
    hostname = asset_data.get('hostname', '') or None

    # Skip records without an IP address if IP is your primary identifier
    if not ip_address:
        log.warning(f"Skipping asset '{hostname}': Missing required IP address.")
        return False

    glpi_type = asset_data.get('glpi_type', '')
    device_type = asset_data.get('type', '')
    os_name = asset_data.get('os', '')
    asset_type = classify_asset_type(glpi_type, device_type, os_name)

    try:
        with pg_conn.cursor() as cur:
            subnet_mask = asset_data.get('subnet_mask', '') or None
            mac_address = asset_data.get('mac', '') or None
            location = asset_data.get('location', '') or None
            criticality = asset_data.get('criticality', '') or None
            owner_email = asset_data.get('owner', '') or None
            source = asset_data.get('source', '') or None
            status = asset_data.get('status', '') or None

            # --- Step 1: Base Table Upsert on ip_address ---
            # Exclude asset_id from the INSERT list so Postgres triggers DEFAULT gen_random_uuid()
            cur.execute("""
                INSERT INTO assets (
                    ip_address,
                    subnet_mask,
                    mac_address,
                    hostname,
                    asset_type,
                    location,
                    criticality,
                    owner_email,
                    source,
                    status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (ip_address) DO UPDATE SET
                    subnet_mask = EXCLUDED.subnet_mask,
                    mac_address = EXCLUDED.mac_address,
                    hostname = EXCLUDED.hostname,
                    asset_type = EXCLUDED.asset_type,
                    location = EXCLUDED.location,
                    criticality = EXCLUDED.criticality,
                    owner_email = EXCLUDED.owner_email,
                    source = EXCLUDED.source,
                    status = EXCLUDED.status,
                    updated_at = NOW()
                RETURNING asset_id;
            """, (
                ip_address,
                subnet_mask,
                mac_address,
                hostname,
                asset_type,
                location,
                criticality,
                owner_email,
                source,
                status
            ))
            
            asset_id = cur.fetchone()[0]

            # --- Step 2: Child Table Upsert ---
            if asset_type == 'server':
                os_version = asset_data.get('osVersion', '') or None
                kernel_version = asset_data.get('kernelVersion', '') or None
                software_raw = asset_data.get('software', '')
                installed_software = {}
                if software_raw:
                    try:
                        installed_software = json.loads(software_raw)
                    except (json.JSONDecodeError, TypeError):
                        installed_software = {}

                cur.execute("""
                    INSERT INTO server_assets (
                        asset_id, os_name, os_version, kernel_version, installed_software
                    )
                    VALUES (%s, %s, %s, %s, %s::jsonb)
                    ON CONFLICT (asset_id) DO UPDATE SET
                        os_name = EXCLUDED.os_name,
                        os_version = EXCLUDED.os_version,
                        kernel_version = EXCLUDED.kernel_version,
                        installed_software = EXCLUDED.installed_software;
                """, (
                    asset_id,
                    os_name or None,
                    os_version,
                    kernel_version,
                    json.dumps(installed_software)
                ))

            elif asset_type == 'endpoint':
                os_version = asset_data.get('osVersion', '') or None
                software_raw = asset_data.get('software', '')
                installed_software = {}
                if software_raw:
                    try:
                        installed_software = json.loads(software_raw)
                    except (json.JSONDecodeError, TypeError):
                        installed_software = {}

                cur.execute("""
                    INSERT INTO endpoint_assets (
                        asset_id, os_name, os_version, installed_software, assigned_user
                    )
                    VALUES (%s, %s, %s, %s::jsonb, %s)
                    ON CONFLICT (asset_id) DO UPDATE SET
                        os_name = EXCLUDED.os_name,
                        os_version = EXCLUDED.os_version,
                        installed_software = EXCLUDED.installed_software,
                        assigned_user = EXCLUDED.assigned_user;
                """, (
                    asset_id,
                    os_name or None,
                    os_version,
                    json.dumps(installed_software),
                    owner_email
                ))

            elif asset_type == 'network_device':
                vendor = asset_data.get('vendor', '') or None
                model = asset_data.get('model', '') or None
                serial_number = asset_data.get('serial', '') or None
                product_number = asset_data.get('product_number', '') or None
                firmware_version = asset_data.get('firmware', '') or None
                network_zone = asset_data.get('network_zone', '') or None

                cur.execute("""
                    INSERT INTO network_device_assets (
                        asset_id, vendor, model, serial_number, product_number,
                        firmware_version, network_zone
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (asset_id) DO UPDATE SET
                        vendor = EXCLUDED.vendor,
                        model = EXCLUDED.model,
                        serial_number = EXCLUDED.serial_number,
                        product_number = EXCLUDED.product_number,
                        firmware_version = EXCLUDED.firmware_version,
                        network_zone = EXCLUDED.network_zone;
                """, (
                    asset_id, vendor, model, serial_number,
                    product_number, firmware_version, network_zone
                ))

        pg_conn.commit()
        log.info(f"Upserted asset for IP: {ip_address} (asset_id={asset_id})")
        return True

    except psycopg2.Error as e:
        log.error(f"PostgreSQL upsert failed for IP {ip_address}: {e}")
        pg_conn.rollback()
        return False
    
def upsert_all_assets(pg_conn, rows):
    """Upsert all assets into the Neon database. Returns (success_count, fail_count)."""
    success = 0
    fail = 0
    for asset_data in rows:
        if upsert_asset(pg_conn, asset_data):
            success += 1
        else:
            fail += 1
    return success, fail


# ============================================================
# DATABASE QUERIES
# ============================================================

def execute_query(cursor, query, params=None, retries=2):
    for attempt in range(1, retries + 2):
        try:
            cursor.execute(query, params or ())
            return cursor.fetchall()
        except mysql.connector.errors.OperationalError as e:
            error_code = getattr(e, 'errno', 0)
            if error_code in (2006, 2013) and attempt <= retries:
                log.warning(f"DB connection lost (attempt {attempt}), reconnecting...")
                time.sleep(DB_RETRY_DELAY)
                cursor.close()
                cursor._connection.reconnect()
                continue
            raise
        except mysql.connector.Error as e:
            log.error(f"Query failed: {e}")
            raise

def query_computers(cursor):
    query = """
    SELECT
        c.id, c.name AS hostname, ct.name AS device_type, m.name AS vendor, cm.name AS model,
        cm.product_number, c.serial, l.name AS location, s.name AS state, u.name AS owner_name,
        os.name AS os_name, osv.name AS os_version, osk.name AS kernel_version, osa.name AS architecture,
        np.mac AS mac_address, ip.name AS ip_address, inet.netmask AS subnet_mask, c.date_mod AS last_updated,
        ic.buy_date AS purchase_date, ic.warranty_duration AS warranty_months,
        (SELECT COUNT(*) FROM glpi_items_tickets it WHERE it.items_id = c.id AND it.itemtype = 'Computer') AS ticket_count
    FROM glpi_computers c
    LEFT JOIN glpi_computertypes ct ON c.computertypes_id = ct.id
    LEFT JOIN glpi_manufacturers m ON c.manufacturers_id = m.id
    LEFT JOIN glpi_computermodels cm ON c.computermodels_id = cm.id
    LEFT JOIN glpi_locations l ON c.locations_id = l.id
    LEFT JOIN glpi_states s ON c.states_id = s.id
    LEFT JOIN glpi_users u ON c.users_id = u.id
    LEFT JOIN glpi_items_operatingsystems ios ON ios.items_id = c.id AND ios.itemtype = 'Computer'
    LEFT JOIN glpi_operatingsystems os ON os.id = ios.operatingsystems_id
    LEFT JOIN glpi_operatingsystemversions osv ON osv.id = ios.operatingsystemversions_id
    LEFT JOIN glpi_operatingsystemkernelversions osk ON osk.id = ios.operatingsystemkernelversions_id
    LEFT JOIN glpi_operatingsystemarchitectures osa ON osa.id = ios.operatingsystemarchitectures_id
    LEFT JOIN glpi_networkports np ON np.items_id = c.id AND np.itemtype = 'Computer'
    LEFT JOIN glpi_ipaddresses ip ON ip.items_id = np.id AND ip.itemtype = 'NetworkPort'
    LEFT JOIN glpi_ipaddresses_ipnetworks ipnet ON ipnet.ipaddresses_id = ip.id
    LEFT JOIN glpi_ipnetworks inet ON inet.id = ipnet.ipnetworks_id
    LEFT JOIN glpi_infocoms ic ON ic.items_id = c.id AND ic.itemtype = 'Computer'
    WHERE c.is_deleted = 0 ORDER BY c.id
    """
    return execute_query(cursor, query)

def query_network_equipment(cursor):
    query = """
    SELECT
        n.id, n.name AS hostname, nt.name AS device_type, m.name AS vendor, nm.name AS model,
        nm.product_number, n.serial, l.name AS location, s.name AS state, n.sysdescr,
        np.mac AS mac_address, ip.name AS ip_address, inet.netmask AS subnet_mask, n.date_mod AS last_updated,
        ic.buy_date AS purchase_date, ic.warranty_duration AS warranty_months,
        fw.version AS firmware_version,
        (SELECT COUNT(*) FROM glpi_items_tickets it WHERE it.items_id = n.id AND it.itemtype = 'NetworkEquipment') AS ticket_count
    FROM glpi_networkequipments n
    LEFT JOIN glpi_networkequipmenttypes nt ON n.networkequipmenttypes_id = nt.id
    LEFT JOIN glpi_manufacturers m ON n.manufacturers_id = m.id
    LEFT JOIN glpi_networkequipmentmodels nm ON n.networkequipmentmodels_id = nm.id
    LEFT JOIN glpi_locations l ON n.locations_id = l.id
    LEFT JOIN glpi_states s ON n.states_id = s.id
    LEFT JOIN glpi_networkports np ON np.items_id = n.id AND np.itemtype = 'NetworkEquipment'
    LEFT JOIN glpi_ipaddresses ip ON ip.items_id = np.id AND ip.itemtype = 'NetworkPort'
    LEFT JOIN glpi_ipaddresses_ipnetworks ipnet ON ipnet.ipaddresses_id = ip.id
    LEFT JOIN glpi_ipnetworks inet ON inet.id = ipnet.ipnetworks_id
    LEFT JOIN glpi_infocoms ic ON ic.items_id = n.id AND ic.itemtype = 'NetworkEquipment'
    LEFT JOIN glpi_items_devicefirmwares link ON n.id = link.items_id AND link.itemtype = 'NetworkEquipment'
    LEFT JOIN glpi_devicefirmwares fw ON link.devicefirmwares_id = fw.id
    WHERE n.is_deleted = 0 ORDER BY n.id
    """
    return execute_query(cursor, query)

def query_software(cursor, computer_id):
    query = """
    SELECT s.name, sv.name AS version
    FROM glpi_items_softwareversions isv
    JOIN glpi_softwareversions sv ON isv.softwareversions_id = sv.id
    JOIN glpi_softwares s ON sv.softwares_id = s.id
    WHERE isv.items_id = %s AND isv.itemtype = 'Computer' AND isv.is_deleted = 0
    """
    try:
        rows = execute_query(cursor, query, (computer_id,))
    except mysql.connector.Error as e:
        log.error(f"Software query failed for computer {computer_id}: {e}")
        return {}

    if not rows:
        return {}

    software_dict = {}
    for row in rows:
        sw_name = row.get('name')
        if sw_name is not None:
            software_dict[str(sw_name)] = '' if row.get('version') is None else str(row.get('version'))
    return software_dict

# ============================================================
# MAIN EXECUTOR
# ============================================================

def main():
    global OUTPUT_FILE, LOG_FILE

    log.info("GLPI Inventory Exporter v3 [INTEGRITY MODE] - Starting")
    log.info(f"Output mode: {OUTPUT_MODE}")

    # --- Resolve symlinks and validate output directory (for CSV mode) ---
    if OUTPUT_MODE in ('csv', 'both'):
        OUTPUT_FILE = resolve_and_validate_output(OUTPUT_FILE)
        LOG_FILE = resolve_and_validate_output(LOG_FILE)
        log.info(f"Resolved output CSV path: {OUTPUT_FILE}")
        log.info(f"Resolved log file path: {LOG_FILE}")

        # Add file logging now that the log file path is resolved
        setup_file_logging(log, LOG_FILE)
        set_secure_permissions(LOG_FILE)

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    rows = []

    # --- Phase 1: Query computers ---
    try:
        computer_rows = query_computers(cursor)
    except mysql.connector.Error:
        computer_rows = []

    for row in computer_rows:
        try:
            hostname = preserve_raw(row, 'hostname')
            if not hostname or is_asset_excluded(hostname):
                continue

            software_dict = query_software(cursor, row.get('id'))
            software_json = json.dumps(software_dict) if software_dict else ''

            rows.append({
                'type': preserve_raw(row, 'device_type'),
                'hostname': hostname,
                'ip': preserve_raw(row, 'ip_address'),
                'subnet_mask': preserve_raw(row, 'subnet_mask'),
                'mac': preserve_raw(row, 'mac_address'),
                'location': preserve_raw(row, 'location'),
                'criticality': map_criticality(preserve_raw(row, 'device_type')),
                'owner': preserve_raw(row, 'owner_name'),
                'source': 'AGENT',
                'status': map_status(preserve_raw(row, 'state')),
                'os': preserve_raw(row, 'os_name'),
                'osVersion': preserve_raw(row, 'os_version'),
                'kernelVersion': preserve_raw(row, 'kernel_version'),
                'software': software_json,
                'vendor': preserve_raw(row, 'vendor'),
                'model': preserve_raw(row, 'model'),
                'product_number': preserve_raw(row, 'product_number'),
                'serial': preserve_raw(row, 'serial'),
                'firmware': '',
                'network_zone': preserve_raw(row, 'location'),
                'glpi_id': preserve_raw(row, 'id'),
                'glpi_type': 'Computer',
                'purchase_date': preserve_raw(row, 'purchase_date'),
                'warranty_end': preserve_raw(row, 'warranty_months'),
                'last_updated': preserve_raw(row, 'last_updated'),
                'ticket_count': preserve_raw(row, 'ticket_count'),
            })
        except Exception as e:
            log.error(f"Error processing computer row: {e}")

    # --- Phase 2: Query network equipment ---
    try:
        net_rows = query_network_equipment(cursor)
    except mysql.connector.Error:
        net_rows = []

    for row in net_rows:
        try:
            hostname = preserve_raw(row, 'hostname')
            if not hostname or is_asset_excluded(hostname):
                continue

            sysdescr = preserve_raw(row, 'sysdescr')
            net_os_name, net_os_version, net_kernel = extract_os_from_sysdescr(sysdescr)

            rows.append({
                'type': preserve_raw(row, 'device_type'),
                'hostname': hostname,
                'ip': preserve_raw(row, 'ip_address'),
                'subnet_mask': preserve_raw(row, 'subnet_mask'),
                'mac': preserve_raw(row, 'mac_address'),
                'location': preserve_raw(row, 'location'),
                'criticality': map_criticality(preserve_raw(row, 'device_type')),
                'owner': '',
                'source': 'MANUAL',
                'status': map_status(preserve_raw(row, 'state')),
                'os': net_os_name if net_os_name else sysdescr,
                'osVersion': net_os_version,
                'kernelVersion': net_kernel,
                'software': '',
                'vendor': preserve_raw(row, 'vendor'),
                'model': preserve_raw(row, 'model'),
                'product_number': preserve_raw(row, 'product_number'),
                'serial': preserve_raw(row, 'serial'),
                'firmware': preserve_raw(row, 'firmware_version'),
                'network_zone': preserve_raw(row, 'location'),
                'glpi_id': preserve_raw(row, 'id'),
                'glpi_type': 'NetworkEquipment',
                'purchase_date': preserve_raw(row, 'purchase_date'),
                'warranty_end': preserve_raw(row, 'warranty_months'),
                'last_updated': preserve_raw(row, 'last_updated'),
                'ticket_count': preserve_raw(row, 'ticket_count'),

            })
        except Exception as e:
            log.error(f"Error processing network row: {e}")

    if not rows:
        log.warning("No assets found to export.")
        cursor.close()
        conn.close()
        return

    log.info(f"Total assets collected: {len(rows)}")

    # --- Phase 3: Write CSV (if mode is csv or both) ---
    if OUTPUT_MODE in ('csv', 'both'):
        atomic_csv_write(rows, CSV_COLUMNS, OUTPUT_FILE, BACKUP_COUNT)
        set_secure_permissions(OUTPUT_FILE)
        log.info(f"CSV exported: {len(rows)} rows to {OUTPUT_FILE}")

    # --- Phase 4: Upsert to Neon PostgreSQL (if mode is postgresql or both) ---
    if OUTPUT_MODE in ('postgresql', 'both'):
        pg_conn = connect_pg()
        if pg_conn:
            success, fail = upsert_all_assets(pg_conn, rows)
            log.info(f"Neon upsert complete: {success} succeeded, {fail} failed")
            pg_conn.close()
        else:
            log.error("Skipping PostgreSQL upsert due to connection failure.")

    cursor.close()
    conn.close()

if __name__ == '__main__':
    main()