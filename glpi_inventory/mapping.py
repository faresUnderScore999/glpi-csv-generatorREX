"""
Mapping and classification functions for GLPI Inventory Exporter.

Provides status/criticality mapping and asset type classification.
"""


def map_criticality(raw_criticality):
    """Map GLPI criticality (if any) to allowed PG values; default to MEDIUM."""
    return 'MEDIUM'


def map_status(raw_state):
    """Map GLPI state name to allowed PostgreSQL status."""
    mapping = {
        'In use': 'ACTIVE',
        'Under repair': 'INACTIVE',
        'In stock': 'INACTIVE',
        'Retired': 'RETIRED',
    }
    if not raw_state:
        return 'ACTIVE'
    return mapping.get(raw_state, 'ACTIVE')


def classify_asset_type(glpi_type, device_type, os_name):
    """
    Classify a GLPI asset into one of: 'ServerAsset', 'EndpointAsset', 'NetworkDeviceAsset'.

    - glpi_type: 'Computer' or 'NetworkEquipment' from GLPI
    - device_type: the GLPI computer/network type name (e.g. 'Server', 'Desktop', 'Laptop')
    - os_name: the operating system name
    """
    if glpi_type == 'NetworkEquipment':
        return 'NetworkDeviceAsset'

    dt_lower = (device_type or '').lower()
    if 'server' in dt_lower:
        return 'ServerAsset'

    os_lower = (os_name or '').lower()
    if any(kw in os_lower for kw in ('server', 'centos', 'rhel', 'debian', 'ubuntu server')):
        return 'ServerAsset'

    return 'EndpointAsset'