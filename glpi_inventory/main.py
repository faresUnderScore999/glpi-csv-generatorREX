"""
Main orchestrator for GLPI Inventory Exporter.

Coordinates the phases:
  1) Connect to GLPI database and query computers + network equipment
  2) Build asset rows with full integrity preservation
  3) Write CSV (if mode is csv or both)
  4) Upsert to Neon PostgreSQL (if mode is postgresql or both)
"""

import json
import logging

from glpi_inventory.config import Config, CSV_COLUMNS
from glpi_inventory.db import glpi_connect, pg_connect
from glpi_inventory.logger import setup_logging, setup_file_logging, set_secure_permissions
from glpi_inventory.mapping import map_criticality, map_status
from glpi_inventory.output_csv import atomic_csv_write
from glpi_inventory.output_pg import upsert_all_assets
from glpi_inventory.parsers import preserve_raw, extract_os_from_sysdescr, is_asset_excluded
from glpi_inventory.queries import query_computers, query_network_equipment, query_software

log = logging.getLogger('glpi_inventory')


def resolve_and_validate_output(path_str):
    """
    Resolve symlinks in the given path string and validate the output directory.

    Returns the resolved absolute path string.
    Raises:
        FileNotFoundError  – if the parent directory does not exist
        PermissionError    – if the parent directory is not writable
        NotADirectoryError – if the parent is not a directory
    """
    from pathlib import Path
    import os

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


def main():
    config = Config()
    log = setup_logging(config)

    log.info("GLPI Inventory Exporter v3 [INTEGRITY MODE] - Starting")
    log.info(f"Output mode: {config.output_mode}")

    # --- Resolve symlinks and validate output directory (for CSV mode) ---
    if config.output_mode in ('csv', 'both'):
        resolved_output = resolve_and_validate_output(config.output_file)
        resolved_log = resolve_and_validate_output(config.log_file)
        config.output_file = resolved_output
        config.log_file = resolved_log
        log.info(f"Resolved output CSV path: {config.output_file}")
        log.info(f"Resolved log file path: {config.log_file}")

        # Add file logging now that the log file path is resolved
        setup_file_logging(log, config.log_file)
        set_secure_permissions(config.log_file)

    conn = glpi_connect(config)
    cursor = conn.cursor(dictionary=True)
    rows = []

    # --- Phase 1: Query computers ---
    try:
        computer_rows = query_computers(cursor)
    except Exception:
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
    except Exception:
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
                'source': 'AGENT',
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
    if config.output_mode in ('csv', 'both'):
        atomic_csv_write(rows, CSV_COLUMNS, config.output_file, config.backup_count)
        set_secure_permissions(config.output_file)
        log.info(f"CSV exported: {len(rows)} rows to {config.output_file}")

    # --- Phase 4: Upsert to Neon PostgreSQL (if mode is postgresql or both) ---
    if config.output_mode in ('postgresql', 'both'):
        pg_conn = pg_connect(config)
        if pg_conn:
            success, fail = upsert_all_assets(pg_conn, rows)
            log.info(f"Neon upsert complete: {success} succeeded, {fail} failed")
            pg_conn.close()
        else:
            log.error("Skipping PostgreSQL upsert due to connection failure.")

    cursor.close()
    conn.close()