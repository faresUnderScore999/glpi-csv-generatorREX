"""
GLPI Assets Inventory Exporter v3 - Pure Data Integrity Edition
===============================================================
Generates an assets_inventory.csv file from GLPI MariaDB database and/or
upserts assets into a PostgreSQL (Neon) database.
Maintains 100% integrity of raw database entries without transformation.
"""

__version__ = "3.1.0"
__author__ = "OMEA Team"