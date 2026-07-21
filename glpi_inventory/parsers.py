"""
Parsing and data-preservation utilities for GLPI Inventory Exporter.

Contains helpers for safe raw-value extraction and sysDescr-based OS parsing.
"""

import re

from glpi_inventory.config import EXCLUDED_ASSETS


def preserve_raw(row, key):
    """Safely fetch raw DB contents without parsing, formatting, or altering null values."""
    if row is None:
        return ''
    val = row.get(key)
    return '' if val is None else str(val)


def extract_os_from_sysdescr(sysdescr):
    """Fallback parser for Network Equipment OS extraction from sysDescr."""
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
    """Check if a hostname is in the excluded assets list."""
    return hostname in EXCLUDED_ASSETS