"""
PostgreSQL (Neon) upsert module for GLPI Inventory Exporter.

Provides functions to upsert assets into a Neon database.
"""

import json
import logging

import psycopg2

from glpi_inventory.mapping import classify_asset_type

log = logging.getLogger('glpi_inventory')


def upsert_asset(pg_conn, asset_data):
    """
    Upsert a single asset into the Neon database using ip_address as the unique key.
    """
    ip_address = asset_data.get('ip', '') or None
    hostname = asset_data.get('hostname', '') or None

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
            if asset_type == 'ServerAsset':
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

            elif asset_type == 'EndpointAsset':
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

            elif asset_type == 'NetworkDeviceAsset':
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