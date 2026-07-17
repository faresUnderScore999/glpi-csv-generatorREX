#!/usr/bin/env python3
"""
GLPI Assets Inventory Exporter v3
Generates an assets_inventory.csv file from GLPI MariaDB database.
Enhanced with CPE fields for vulnerability/CVE matching.

CSV Columns (31):
  type,hostname,ip,subnet_mask,mac,location,criticality,owner,source,status,
  os,osVersion,kernelVersion,architecture,ports,software,
  vendor,model,product_number,serial,firmware,
  cpe,os_cpe,software_cpe,network_zone,
  glpi_id,glpi_type,purchase_date,warranty_end,last_updated,ticket_count

Improvements v3:
  - Proper date parsing with python-dateutil
  - Accurate warranty calculation with relativedelta
  - CPE fields marked as approximations (configurable)
  - Configurable asset exclusions, criticality, zones
  - Atomic CSV writes with backup
  - Python logging module with file rotation
  - Retry on database disconnection
  - Better error handling with structured logging
  - Flexible OS detection for network equipment
"""

import csv
import json
import logging
import os
import re
import shutil
import sys
import time
from datetime import datetime, date
from pathlib import Path
from logging.handlers import RotatingFileHandler
import mysql.connector
from dateutil.relativedelta import relativedelta
from dateutil.parser import parse as parse_date

# ============================================================
# CONFIGURATION

# ============================================================

DB_CONFIG = {
    'host': '172.17.0.1',
    'port': 3306,
    'user': 'glpi',
    'password': 'glpi',
    'database': 'glpi',
}

# Asset names to exclude (e.g., test/auto-created entries)
EXCLUDED_ASSETS = ['Yamaha-Kali-Laptop']

# Output settings
OUTPUT_FILE = 'assets_inventory.csv'
BACKUP_COUNT = 3
LOG_FILE = 'generate_inventory.log'
LOG_LEVEL = logging.INFO

# DB retry settings
DB_RETRY_COUNT = 3
DB_RETRY_DELAY = 2  # seconds

# Mark CPE fields as approximations? (True = add "(approx)" suffix)
CPE_APPROXIMATION_MODE = True
CPE_APPROXIMATION_SUFFIX = ' [approx]'

# ============================================================
# CONFIGURABLE MAPPINGS (override these to match your environment)
# ============================================================

# Device type → Criticality
CRITICALITY_MAP = {
    'Server': 'HIGH',
    'Switch': 'HIGH',
    'Router': 'HIGH',
    'Firewall': 'CRITICAL',
    'Desktop': 'LOW',
    'Laptop': 'MEDIUM',
    'Access Point': 'MEDIUM',
}

# Device type → Network Zone
ZONE_MAP = {
    'Firewall': 'DMZ',
    'Access Point': 'WIFI',
    'Switch': 'LAN',
    'Router': 'LAN',
    # Computers: determined by location keywords below
}

# Location keywords → Network Zone (for computers)
LOCATION_ZONE_MAP = [
    ('datacenter', 'DMZ'),
    ('server room', 'DMZ'),
    ('dmz', 'DMZ'),
    ('wifi', 'WIFI'),
    ('guest', 'GUEST'),
]

# Device type → Default owner email
DEFAULT_OWNER_MAP = {
    'NETWORK': 'netops@company.com',
    'SERVER': 'sysadmin@company.com',
    'ENDPOINT': 'helpdesk@company.com',
}

# Owner username → Email domain
OWNER_EMAIL_DOMAIN = 'company.com'
FALLBACK_OWNER_EMAIL = 'admin@company.com'

# State → Status mapping
STATUS_MAP = {
    'In use': 'ACTIVE',
    'In stock': 'INACTIVE',
    'Under repair': 'MAINTENANCE',
    'Broken': 'DECOMMISSIONED',
}

# Vendor name normalization for CPE generation
VENDOR_CPE_MAP = {
    'dell': 'dell',
    'hp': 'hp',
    'hewlett packard': 'hp',
    'lenovo': 'lenovo',
    'cisco': 'cisco',
    'canon': 'canon',
    'samsung': 'samsung',
    'lg': 'lg',
    'microsoft': 'microsoft',
    'apple': 'apple',
    'fortinet': 'fortinet',
    'aruba': 'aruba',
    'vmware': 'vmware',
    'adobe': 'adobe',
    'apc': 'apc',
    'symantec': 'symantec',
    'broadcom': 'broadcom',
    '7-zip': '7-zip',
    'slack': 'slack',
}

# Software name → CPE (vendor, product) for known apps
SOFTWARE_CPE_MAP = {
    'office': ('microsoft', 'office'),
    'windows': None,  # Skip (handled as OS CPE)
    'vscode': ('microsoft', 'visual_studio_code'),
    'visual_studio_code': ('microsoft', 'visual_studio_code'),
    'photoshop': ('adobe', 'photoshop'),
    'norton': ('symantec', 'norton_360'),
    'norton_360': ('symantec', 'norton_360'),
    'vmware': ('vmware', 'workstation'),
    'workstation': ('vmware', 'workstation'),
    'slack': ('slack', 'slack'),
    '7zip': ('7-zip', '7-zip'),
    '7-zip': ('7-zip', '7-zip'),
}

# ============================================================
# CSV COLUMNS
# ============================================================

CSV_COLUMNS = [
    'type', 'hostname', 'ip', 'subnet_mask', 'mac', 'location', 'criticality',
    'owner', 'source', 'status', 'os', 'osVersion', 'kernelVersion',
    'architecture', 'ports', 'software',
    'vendor', 'model', 'product_number', 'serial', 'firmware',
    'cpe', 'os_cpe', 'software_cpe', 'network_zone',
    'glpi_id', 'glpi_type', 'purchase_date', 'warranty_end',
    'last_updated', 'ticket_count',
]

# ============================================================
# LOGGING SETUP
# ============================================================

def setup_logging():
    """Configure logging to both console and file with rotation."""
    logger = logging.getLogger('glpi_inventory')
    logger.setLevel(LOG_LEVEL)

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(LOG_LEVEL)
    console.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(console)

    # File handler (always append)
    try:
        fh = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(fh)
    except (IOError, PermissionError) as e:
        logger.warning(f"Could not create log file {LOG_FILE}: {e}")

    return logger


log = setup_logging()

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe(val, default=''):
    """Return value or default if None."""
    return val if val is not None else default


def safe_get(row, key):
    """Safely get a value from a dict, returning '' if missing or None."""
    try:
        val = row.get(key)
        return val if val is not None else ''
    except (AttributeError, KeyError):
        return ''


def safe_int(val, default=0):
    """Convert to int safely."""
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def connect_db():
    """Connect to MySQL/MariaDB with retry logic."""
    for attempt in range(1, DB_RETRY_COUNT + 1):
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            log.info(f"Connected to database {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}")
            return conn
        except mysql.connector.Error as e:
            log.error(f"DB connection attempt {attempt}/{DB_RETRY_COUNT} failed: {e}")
            if attempt < DB_RETRY_COUNT:
                log.info(f"Retrying in {DB_RETRY_DELAY}s...")
                time.sleep(DB_RETRY_DELAY)
            else:
                log.critical("All database connection attempts failed. Exiting.")
                sys.exit(1)


def normalize_vendor(name):
    """Normalize vendor name to lowercase CPE-friendly identifier."""
    if not name:
        return ''
    v = name.lower().strip()
    # Check known mappings first
    for pattern, replacement in VENDOR_CPE_MAP.items():
        if pattern in v:
            return replacement
    # Generic fallback
    cleaned = re.sub(r'[^a-z0-9]', '', v)
    return cleaned if cleaned else 'unknown'


def normalize_model(name):
    """Normalize model name for CPE (lowercase)."""
    if not name:
        return ''
    return re.sub(r'[^a-z0-9._-]', '', name.lower().strip())


def build_hardware_cpe(vendor, model):
    """
    Build an approximate CPE 2.3 string for hardware (h:).
    NOTE: This is an APPROXIMATION. For production CVE matching,
    use the NVD CPE dictionary API to get official CPEs.
    """
    if not vendor or not model:
        return ''
    v = normalize_vendor(vendor)
    m = normalize_model(model)
    if not v or not m:
        return ''
    cpe = f'cpe:2.3:h:{v}:{m}:*:*:*:*:*:*:*:*'
    if CPE_APPROXIMATION_MODE:
        cpe += CPE_APPROXIMATION_SUFFIX
    return cpe


def build_os_cpe(os_name, os_version):
    """
    Build an approximate CPE 2.3 string for OS (o:).
    NOTE: This is an APPROXIMATION. For production CVE matching,
    use the NVD CPE dictionary API to get official CPEs.
    """
    if not os_name:
        return ''

    os_lower = os_name.lower().strip()
    vendor = ''
    product = ''

    # Map known OS
    if 'windows' in os_lower or 'microsoft' in os_lower:
        vendor = 'microsoft'
        if '11' in os_lower:
            product = 'windows_11'
        elif '10' in os_lower:
            product = 'windows_10'
        elif 'server' in os_lower:
            product = 'windows_server'
        elif '8' in os_lower:
            product = 'windows_8'
        elif '7' in os_lower:
            product = 'windows_7'
        else:
            product = 'windows'
    elif 'ubuntu' in os_lower:
        vendor = 'canonical'
        product = 'ubuntu_linux'
    elif 'debian' in os_lower:
        vendor = 'debian'
        product = 'debian_linux'
    elif 'centos' in os_lower:
        vendor = 'centos'
        product = 'centos'
    elif 'rhel' in os_lower or 'red hat' in os_lower:
        vendor = 'redhat'
        product = 'enterprise_linux'
    elif 'vmware' in os_lower or 'esxi' in os_lower:
        vendor = 'vmware'
        product = 'esxi'
    elif 'ios' in os_lower and 'cisco' in os_lower:
        vendor = 'cisco'
        product = 'ios'
    else:
        # Generic CPE
        vendor_try = normalize_vendor(os_name)
        if vendor_try:
            vendor = vendor_try
            product = re.sub(r'[^a-z0-9]', '_', os_lower)

    if not vendor or not product:
        return ''

    ver = normalize_model(os_version) if os_version else '*'
    cpe = f'cpe:2.3:o:{vendor}:{product}:{ver}:*:*:*:*:*:*:*'
    if CPE_APPROXIMATION_MODE:
        cpe += CPE_APPROXIMATION_SUFFIX
    return cpe


def build_sw_cpe_dict(software_dict):
    """
    Build software CPE mappings from a software dict {name: version}.
    NOTE: This is an APPROXIMATION. For production CVE matching,
    use the NVD CPE dictionary API to get official CPEs.
    """
    if not software_dict:
        return ''
    cpe_map = {}
    for sw_name, sw_version in software_dict.items():
        try:
            sw_lower = sw_name.lower().strip()

            # Check known mapping first
            known = SOFTWARE_CPE_MAP.get(sw_lower)
            if known is None:
                continue  # Skip (e.g., 'windows')
            if known:
                vendor, product = known
            else:
                # Generic fallback
                vendor = normalize_vendor(sw_name)
                product = re.sub(r'[^a-z0-9]', '_', sw_lower)
                if not vendor:
                    continue

            ver = normalize_model(sw_version) if sw_version else '*'
            cpe_key = f'{product}:{ver}'
            cpe_val = f'cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*'
            if CPE_APPROXIMATION_MODE:
                cpe_val += CPE_APPROXIMATION_SUFFIX
            cpe_map[cpe_key] = cpe_val
        except Exception as e:
            log.debug(f"Failed to build CPE for software '{sw_name}': {e}")
            continue
    return json.dumps(cpe_map) if cpe_map else ''


def map_criticality(device_type, glpi_id=None):
    """Map GLPI device type to criticality level. Configurable via CRITICALITY_MAP."""
    return CRITICALITY_MAP.get(safe(device_type), 'MEDIUM')


def map_status(state_name):
    """Map GLPI state to asset status."""
    return STATUS_MAP.get(safe(state_name), 'ACTIVE')


def map_network_zone(device_type, location):
    """Determine network zone based on device type and location keywords."""
    dt = safe(device_type)
    # Device type based
    if dt in ZONE_MAP:
        return ZONE_MAP[dt]
    # Location keyword based
    loc = safe(location).lower()
    for keyword, zone in LOCATION_ZONE_MAP:
        if keyword in loc:
            return zone
    # Default for computers
    return 'LAN'


def build_owner_email(owner_name, device_type_label):
    """Build an owner email. Falls back to type-based default."""
    name = safe(owner_name)
    if name:
        return f"{name}@{OWNER_EMAIL_DOMAIN}"
    # Use default based on asset type
    dt = map_device_type(device_type_label)
    return DEFAULT_OWNER_MAP.get(dt, FALLBACK_OWNER_EMAIL)


def map_device_type(glpi_type):
    """Map GLPI device type to CSV format types."""
    t = safe(glpi_type)
    if t in ('Switch', 'Router', 'Firewall', 'Access Point'):
        return 'NETWORK'
    elif t == 'Server':
        return 'SERVER'
    elif t in ('Desktop', 'Laptop'):
        return 'ENDPOINT'
    return 'ENDPOINT'


def calc_warranty_end(purchase_date, warranty_months):
    """Calculate warranty end date using accurate relativedelta months."""
    if not purchase_date or not warranty_months:
        return ''
    try:
        if isinstance(purchase_date, (datetime, date)):
            start = purchase_date
        else:
            # Try flexible parsing
            start = parse_date(str(purchase_date))
        months = safe_int(warranty_months)
        if months <= 0:
            return ''
        end = start + relativedelta(months=months)
        return end.strftime('%Y-%m-%d')
    except (ValueError, TypeError, Exception) as e:
        log.debug(f"Could not calculate warranty end: purchase_date={purchase_date}, months={warranty_months}: {e}")
        return ''


def format_date(d):
    """Format a date/timestamp to YYYY-MM-DD string. Handles multiple types."""
    if not d:
        return ''
    try:
        if isinstance(d, datetime):
            return d.strftime('%Y-%m-%d')
        elif isinstance(d, date):
            return d.strftime('%Y-%m-%d')
        else:
            # Try flexible parsing
            parsed = parse_date(str(d))
            return parsed.strftime('%Y-%m-%d')
    except (ValueError, TypeError, Exception) as e:
        log.debug(f"Could not format date {d}: {e}")
        return ''


def atomic_csv_write(rows, columns, output_file, backup_count):
    """Write CSV atomically: write to temp file, then rename. Keep backups."""
    temp_file = output_file + '.tmp'

    try:
        # Write to temp file
        with open(temp_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        log.debug(f"Wrote {len(rows)} rows to temp file {temp_file}")

        # Rotate backups
        if os.path.exists(output_file):
            for i in range(backup_count - 1, 0, -1):
                src = f"{output_file}.{i}"
                dst = f"{output_file}.{i + 1}"
                if os.path.exists(src):
                    shutil.move(src, dst)
            # Move current to .1
            shutil.move(output_file, output_file + '.1')
            log.debug(f"Rotated backups (keeping {backup_count})")

        # Atomic rename
        shutil.move(temp_file, output_file)
        log.debug(f"Atomically renamed {temp_file} → {output_file}")

    except (IOError, OSError, PermissionError) as e:
        log.error(f"Failed to write CSV: {e}")
        # Clean up temp file if it exists
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass
        raise


# ============================================================
# DATABASE QUERIES
# ============================================================

def execute_query(cursor, query, params=None, retries=2):
    """Execute a query with automatic retry on connection loss."""
    for attempt in range(1, retries + 2):
        try:
            cursor.execute(query, params or ())
            return cursor.fetchall()
        except mysql.connector.errors.OperationalError as e:
            error_code = getattr(e, 'errno', 0)
            # Connection-related errors: 2006 (gone away), 2013 (lost connection)
            if error_code in (2006, 2013) and attempt <= retries:
                log.warning(f"DB connection lost (attempt {attempt}), reconnecting...")
                time.sleep(DB_RETRY_DELAY)
                # Reconnect
                cursor.close()
                cursor._connection.reconnect()
                continue
            raise
        except mysql.connector.Error as e:
            log.error(f"Query failed: {e}\nQuery: {query[:200]}...")
            raise


def query_computers(cursor):
    """Query all computers with full details."""
    query = """
    SELECT
        c.id,
        c.name AS hostname,
        ct.name AS device_type,
        m.name AS vendor,
        cm.name AS model,
        cm.product_number,
        c.serial,
        l.name AS location,
        s.name AS state,
        u.name AS owner_name,
        os.name AS os_name,
        osv.name AS os_version,
        osk.name AS kernel_version,
        osa.name AS architecture,
        np.mac AS mac_address,
        ip.name AS ip_address,
        inet.netmask AS subnet_mask,
        c.date_mod AS last_updated,
        ic.buy_date AS purchase_date,
        ic.warranty_duration AS warranty_months,
        (SELECT COUNT(*) FROM glpi_items_tickets it
         WHERE it.items_id = c.id AND it.itemtype = 'Computer') AS ticket_count
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
    WHERE c.is_deleted = 0
    ORDER BY c.id
    """
    return execute_query(cursor, query)


def query_network_equipment(cursor):
    """Query all network equipment."""
    query = """
    SELECT
        n.id,
        n.name AS hostname,
        nt.name AS device_type,
        m.name AS vendor,
        nm.name AS model,
        nm.product_number,
        n.serial,
        l.name AS location,
        s.name AS state,
        n.sysdescr,
        np.mac AS mac_address,
        ip.name AS ip_address,
        inet.netmask AS subnet_mask,
        n.date_mod AS last_updated,
        ic.buy_date AS purchase_date,
        ic.warranty_duration AS warranty_months,
        (SELECT COUNT(*) FROM glpi_items_tickets it
         WHERE it.items_id = n.id AND it.itemtype = 'NetworkEquipment') AS ticket_count
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
    WHERE n.is_deleted = 0
    ORDER BY n.id
    """
    return execute_query(cursor, query)


def query_software(cursor, computer_id):
    """Get installed software for a computer as a dict {name: version}."""
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
        try:
            sw_name = safe(row.get('name', ''))
            sw_version = safe(row.get('version', ''))
            if not sw_name:
                continue
            # Simplify names for consistent mapping
            sw_lower = sw_name.lower()
            if 'microsoft office' in sw_lower:
                sw_name = 'office'
            elif 'microsoft windows' in sw_lower:
                sw_name = 'windows'
            elif 'visual studio' in sw_lower:
                sw_name = 'vscode'
            elif 'adobe photoshop' in sw_lower:
                sw_name = 'photoshop'
            elif 'norton' in sw_lower:
                sw_name = 'norton'
            elif 'vmware' in sw_lower:
                sw_name = 'vmware'
            elif 'slack' in sw_lower:
                sw_name = 'slack'
            elif '7-zip' in sw_lower or '7zip' in sw_lower:
                sw_name = '7zip'
            else:
                sw_name = re.sub(r'[^a-z0-9]', '_', sw_lower).strip('_')
            software_dict[sw_name] = sw_version
        except Exception as e:
            log.debug(f"Failed to process software row: {e}")
            continue

    return software_dict


def extract_os_from_sysdescr(sysdescr):
    """
    Try to extract OS name and version from network device sysDescr.
    Example: 'Cisco IOS Software, C9200 Software (C9200-UNIVERSALK9-M), Version 17.3.3'
    """
    if not sysdescr:
        return '', '', ''
    desc = str(sysdescr)
    desc_lower = desc.lower()

    if 'cisco ios' in desc_lower:
        os_name = 'Cisco IOS'
        # Try to extract version
        m = re.search(r'version\s+(\S+)', desc, re.IGNORECASE)
        os_version = m.group(1) if m else ''
        return os_name, os_version, ''
    elif 'fortinet' in desc_lower or 'fortigate' in desc_lower:
        os_name = 'FortiOS'
        m = re.search(r'version\s+(\S+)', desc, re.IGNORECASE)
        os_version = m.group(1) if m else ''
        return os_name, os_version, ''
    elif 'aruba' in desc_lower:
        os_name = 'ArubaOS'
        m = re.search(r'version\s+(\S+)', desc, re.IGNORECASE)
        os_version = m.group(1) if m else ''
        return os_name, os_version, ''
    elif 'linux' in desc_lower:
        os_name = 'Linux'
        m = re.search(r'(\d+\.\d+\.\d+[^\s]*)', desc)
        os_version = m.group(1) if m else ''
        return os_name, os_version, ''

    return '', '', ''


def is_asset_excluded(hostname):
    """Check if an asset should be excluded."""
    return safe(hostname) in EXCLUDED_ASSETS


# ============================================================
# MAIN
# ============================================================

def main():
    log.info("=" * 60)
    log.info("GLPI Inventory Exporter v3 - Starting")
    log.info(f"Excluded assets: {EXCLUDED_ASSETS}")
    log.info(f"CPE approximation mode: {CPE_APPROXIMATION_MODE}")
    log.info("=" * 60)

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)

    rows = []
    skipped = 0
    total_computers = 0
    total_network = 0
    errors = 0

    # --- Phase 1: Query computers ---
    log.info("\n📋 Phase 1: Querying computers...")
    try:
        computer_rows = query_computers(cursor)
        log.info(f"   Found {len(computer_rows)} computer records")
    except mysql.connector.Error as e:
        log.error(f"   ❌ Computer query failed: {e}")
        computer_rows = []
        errors += 1

    for row in computer_rows:
        try:
            hostname = safe_get(row, 'hostname')
            if not hostname:
                skipped += 1
                continue
            if is_asset_excluded(hostname):
                log.debug(f"   Skipping excluded asset: {hostname}")
                skipped += 1
                continue

            device_type = map_device_type(row.get('device_type'))
            vendor = safe_get(row, 'vendor')
            model = safe_get(row, 'model')
            os_name = safe_get(row, 'os_name')
            os_version = safe_get(row, 'os_version')
            product_number = safe_get(row, 'product_number')

            # Get software
            software_dict = query_software(cursor, row.get('id'))
            software_json = json.dumps(software_dict) if software_dict else ''

            # Build CPE strings (approximate)
            hw_cpe = build_hardware_cpe(vendor, model)
            os_cpe = build_os_cpe(os_name, os_version)
            sw_cpe = build_sw_cpe_dict(software_dict)

            purchase_date = safe_get(row, 'purchase_date')
            warranty_months = safe_get(row, 'warranty_months')
            warranty_end = calc_warranty_end(purchase_date, warranty_months)

            glpi_id = str(row.get('id') or '')

            rows.append({
                'type': device_type,
                'hostname': hostname,
                'ip': safe_get(row, 'ip_address'),
                'subnet_mask': safe_get(row, 'subnet_mask'),
                'mac': safe_get(row, 'mac_address'),
                'location': safe_get(row, 'location'),
                'criticality': map_criticality(row.get('device_type'), row.get('id')),
                'owner': build_owner_email(row.get('owner_name'), row.get('device_type')),
                'source': 'AGENT',
                'status': map_status(row.get('state')),
                'os': os_name,
                'osVersion': os_version,
                'kernelVersion': safe_get(row, 'kernel_version'),
                'architecture': safe_get(row, 'architecture'),
                'ports': '',
                'software': software_json,
                'vendor': vendor,
                'model': model,
                'product_number': product_number,
                'serial': safe_get(row, 'serial'),
                'firmware': '',
                'cpe': hw_cpe,
                'os_cpe': os_cpe,
                'software_cpe': sw_cpe,
                'network_zone': map_network_zone(row.get('device_type'), row.get('location')),
                'glpi_id': glpi_id,
                'glpi_type': 'Computer',
                'purchase_date': purchase_date,
                'warranty_end': warranty_end,
                'last_updated': format_date(row.get('last_updated')),
                'ticket_count': str(safe_int(row.get('ticket_count'))),
            })
            total_computers += 1

        except Exception as e:
            log.error(f"⚠️ Error processing computer '{safe_get(row, 'hostname')}': {e}")
            skipped += 1
            errors += 1

    # --- Phase 2: Query network equipment ---
    log.info("📋 Phase 2: Querying network equipment...")
    try:
        net_rows = query_network_equipment(cursor)
        log.info(f"   Found {len(net_rows)} network equipment records")
    except mysql.connector.Error as e:
        log.error(f"   ❌ Network equipment query failed: {e}")
        net_rows = []
        errors += 1

    for row in net_rows:
        try:
            hostname = safe_get(row, 'hostname')
            if not hostname:
                skipped += 1
                continue
            if is_asset_excluded(hostname):
                log.debug(f"   Skipping excluded asset: {hostname}")
                skipped += 1
                continue

            device_type = map_device_type(row.get('device_type'))
            vendor = safe_get(row, 'vendor')
            model = safe_get(row, 'model')
            product_number = safe_get(row, 'product_number')

            # Try to extract OS from sysDescr
            sysdescr = safe_get(row, 'sysdescr')
            net_os_name, net_os_version, net_kernel = extract_os_from_sysdescr(sysdescr)
            firmware = net_os_version  # Use OS version as firmware version

            # Build hardware CPE
            hw_cpe = build_hardware_cpe(vendor, model)
            os_cpe = build_os_cpe(net_os_name, net_os_version) if net_os_name else ''

            purchase_date = safe_get(row, 'purchase_date')
            warranty_months = safe_get(row, 'warranty_months')
            warranty_end = calc_warranty_end(purchase_date, warranty_months)

            glpi_id = str(row.get('id') or '')

            rows.append({
                'type': device_type,
                'hostname': hostname,
                'ip': safe_get(row, 'ip_address'),
                'subnet_mask': safe_get(row, 'subnet_mask'),
                'mac': safe_get(row, 'mac_address'),
                'location': safe_get(row, 'location'),
                'criticality': map_criticality(row.get('device_type'), row.get('id')),
                'owner': build_owner_email(None, row.get('device_type')),
                'source': 'MANUAL',
                'status': map_status(row.get('state')),
                'os': net_os_name,
                'osVersion': net_os_version,
                'kernelVersion': net_kernel,
                'architecture': '',
                'ports': '',
                'software': '',
                'vendor': vendor,
                'model': model,
                'product_number': product_number,
                'serial': safe_get(row, 'serial'),
                'firmware': firmware,
                'cpe': hw_cpe,
                'os_cpe': os_cpe,
                'software_cpe': '',
                'network_zone': map_network_zone(row.get('device_type'), row.get('location')),
                'glpi_id': glpi_id,
                'glpi_type': 'NetworkEquipment',
                'purchase_date': purchase_date,
                'warranty_end': warranty_end,
                'last_updated': format_date(row.get('last_updated')),
                'ticket_count': str(safe_int(row.get('ticket_count'))),
            })
            total_network += 1

        except Exception as e:
            log.error(f"⚠️ Error processing network device '{safe_get(row, 'hostname')}': {e}")
            skipped += 1
            errors += 1

    # --- Phase 3: Write CSV ---
    log.info("📋 Phase 3: Writing CSV...")
    try:
        atomic_csv_write(rows, CSV_COLUMNS, OUTPUT_FILE, BACKUP_COUNT)
    except Exception as e:
        log.critical(f"❌ Failed to write output file: {e}")
        cursor.close()
        conn.close()
        sys.exit(1)

    # --- Summary ---
    log.info("=" * 60)
    log.info(f"✅ Generated {OUTPUT_FILE} with {len(rows)} assets")
    log.info(f"\n📊 Summary:")
    log.info(f"   Computers:  {total_computers}")
    log.info(f"   Network:    {total_network}")
    log.info(f"   Total:      {len(rows)}")

    # Count by type
    type_counts = {}
    for r in rows:
        t = safe(r.get('type', 'UNKNOWN'))
        type_counts[t] = type_counts.get(t, 0) + 1
    for t, c in sorted(type_counts.items()):
        log.info(f"   {t}: {c}")

    # CPE coverage
    cpe_count = sum(1 for r in rows if r.get('cpe'))
    os_cpe_count = sum(1 for r in rows if r.get('os_cpe'))
    sw_cpe_count = sum(1 for r in rows if r.get('software_cpe'))
    log.info(f"\n🔐 CPE Coverage:")
    log.info(f"   Hardware CPE: {cpe_count}/{len(rows)} devices")
    log.info(f"   OS CPE:       {os_cpe_count}/{len(rows)} devices")
    log.info(f"   Software CPE: {sw_cpe_count}/{len(rows)} devices")

    if CPE_APPROXIMATION_MODE:
        log.info(f"\n⚠️  NOTE: CPE fields are marked as approximations ('{CPE_APPROXIMATION_SUFFIX}').")
        log.info(f"   For production CVE matching, validate CPEs against the NVD CPE dictionary API.")

    if skipped:
        log.info(f"\n⚠️  Skipped {skipped} assets (excluded or errors)")
    if errors:
        log.info(f"\n❌  {errors} errors occurred (see log file: {LOG_FILE})")

    log.info("=" * 60)

    cursor.close()
    conn.close()


if __name__ == '__main__':
    main()