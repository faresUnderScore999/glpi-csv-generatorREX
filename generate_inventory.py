#!/usr/bin/env python3
"""
GLPI Assets Inventory Exporter v3 - Pure Data Integrity Edition
Generates an assets_inventory.csv file from GLPI MariaDB database.
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
import sys
import time
from datetime import datetime, date
from pathlib import Path
from logging.handlers import RotatingFileHandler
import mysql.connector

# ============================================================
# CONFIGURATION

DB_CONFIG = {
    'host': '172.17.0.1',
    'port': 3306,
    'user': 'glpi',
    'password': 'glpi',
    'database': 'glpi',
}

# Asset names to exclude
EXCLUDED_ASSETS = ['Yamaha-Kali-Laptop']

# Output settings
OUTPUT_FILE = 'assets_inventory.csv'
BACKUP_COUNT = 3
LOG_FILE = 'generate_inventory.log'
LOG_LEVEL = logging.INFO

# DB retry settings
DB_RETRY_COUNT = 3
DB_RETRY_DELAY = 2  # seconds

# ============================================================
# CSV COLUMNS
# ============================================================

CSV_COLUMNS = [
    'type', 'hostname', 'ip', 'subnet_mask', 'mac', 'location', 'criticality',
    'owner', 'source', 'status', 'os', 'osVersion', 'kernelVersion',
    'architecture', 'ports', 'software',
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
    log.info("GLPI Inventory Exporter v3 [INTEGRITY MODE] - Starting")
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
                'criticality': preserve_raw(row, 'device_type'),
                'owner': preserve_raw(row, 'owner_name'),
                'source': 'AGENT',
                'status': preserve_raw(row, 'state'),
                'os': preserve_raw(row, 'os_name'),
                'osVersion': preserve_raw(row, 'os_version'),
                'kernelVersion': preserve_raw(row, 'kernel_version'),
                'architecture': preserve_raw(row, 'architecture'),
                'ports': '',
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
                'criticality': preserve_raw(row, 'device_type'),
                'owner': '',
                'source': 'MANUAL',
                'status': preserve_raw(row, 'state'),
                'os': net_os_name if net_os_name else sysdescr,
                'osVersion': net_os_version,
                'kernelVersion': net_kernel,
                'architecture': '',
                'ports': '',
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

    # --- Phase 3: Write CSV ---
    if rows:
        atomic_csv_write(rows, CSV_COLUMNS, OUTPUT_FILE, BACKUP_COUNT)
        log.info(f"Successfully exported {len(rows)} raw assets without CPE strings.")
    
    cursor.close()
    conn.close()

if __name__ == '__main__':
    main()