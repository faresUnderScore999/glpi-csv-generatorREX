"""
SQL query definitions and execution helpers for GLPI Inventory Exporter.

Contains all raw SQL queries for computers, network equipment, and software,
along with a retry-aware query executor.
"""

import logging
import time

import mysql.connector

log = logging.getLogger('glpi_inventory')


def execute_query(cursor, query, params=None, retries=2):
    """Execute a query with automatic reconnection on connection-loss errors."""
    for attempt in range(1, retries + 2):
        try:
            cursor.execute(query, params or ())
            return cursor.fetchall()
        except mysql.connector.errors.OperationalError as e:
            error_code = getattr(e, 'errno', 0)
            if error_code in (2006, 2013) and attempt <= retries:
                log.warning(f"DB connection lost (attempt {attempt}), reconnecting...")
                time.sleep(2)
                cursor.close()
                cursor._connection.reconnect()
                continue
            raise
        except mysql.connector.Error as e:
            log.error(f"Query failed: {e}")
            raise


def query_computers(cursor):
    """Fetch all non-deleted computers with their inventory details."""
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
    """Fetch all non-deleted network equipment with their inventory details."""
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
    """Fetch installed software for a given computer ID. Returns a dict of {name: version}."""
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