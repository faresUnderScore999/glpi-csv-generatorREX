"""
Configuration module for GLPI Inventory Exporter.

Loads all settings from environment variables (via .env file) and provides
a typed Config dataclass and constants.
"""

import logging
import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================
load_dotenv()


def _parse_bool(val):
    """Parse a string as a boolean. Accepts 'true'/'false', '1'/'0', 'yes'/'no' (case-insensitive)."""
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    return s in ('true', '1', 'yes', 'y')


# ============================================================
# CSV COLUMNS (constant)
# ============================================================
CSV_COLUMNS = [
    'type', 'hostname', 'ip', 'subnet_mask', 'mac', 'location', 'criticality',
    'owner', 'source', 'status', 'os', 'osVersion', 'kernelVersion',
    'software',
    'vendor', 'model', 'product_number', 'serial', 'firmware',
    'network_zone', 'glpi_id', 'glpi_type', 'purchase_date', 'warranty_end',
    'last_updated', 'ticket_count', 'organization',
]


# ============================================================
# EXCLUDED ASSETS (constant)
# ============================================================
EXCLUDED_ASSETS_RAW = os.getenv('EXCLUDED_ASSETS', '')
EXCLUDED_ASSETS = [a.strip() for a in EXCLUDED_ASSETS_RAW.split(',') if a.strip()]


@dataclass
class Config:
    """Typed configuration dataclass. Populated from environment variables."""

    # --- GLPI (MySQL) connection ---
    db_host: str = field(default_factory=lambda: os.getenv('DB_HOST', '172.17.0.1'))
    db_port: int = field(default_factory=lambda: int(os.getenv('DB_PORT', '3306')))
    db_user: str = field(default_factory=lambda: os.getenv('DB_USER', 'glpi'))
    db_password: str = field(default_factory=lambda: os.getenv('DB_PASSWORD', 'glpi'))
    db_name: str = field(default_factory=lambda: os.getenv('DB_NAME', 'glpi'))

    # SSL connection parameters for remote GLPI databases
    db_ssl_ca: str | None = field(default_factory=lambda: os.getenv('DB_SSL_CA'))
    db_ssl_cert: str | None = field(default_factory=lambda: os.getenv('DB_SSL_CERT'))
    db_ssl_key: str | None = field(default_factory=lambda: os.getenv('DB_SSL_KEY'))
    db_ssl_verify_cert: bool | None = field(default_factory=lambda: _parse_bool(os.getenv('DB_SSL_VERIFY_CERT')) if os.getenv('DB_SSL_VERIFY_CERT') is not None else None)
    db_ssl_verify_identity: bool | None = field(default_factory=lambda: _parse_bool(os.getenv('DB_SSL_VERIFY_IDENTITY')) if os.getenv('DB_SSL_VERIFY_IDENTITY') is not None else None)
    db_use_pure: bool | None = field(default_factory=lambda: _parse_bool(os.getenv('DB_USE_PURE')) if os.getenv('DB_USE_PURE') is not None else None)

    # --- Neon (PostgreSQL) connection ---
    pg_dsn: str = field(default_factory=lambda: os.getenv('PG_DSN', ''))
    pg_connect_timeout: int = field(default_factory=lambda: int(os.getenv('PG_CONNECT_TIMEOUT', '10')))

    # --- Output mode ---
    # 'csv' | 'postgresql' | 'both'
    output_mode: str = field(default_factory=lambda: os.getenv('OUTPUT_MODE', 'csv').strip().lower())

    # Output settings (used when output_mode is 'csv' or 'both')
    output_file: str = field(default_factory=lambda: os.getenv('OUTPUT_FILE', 'assets_inventory.csv'))
    backup_count: int = field(default_factory=lambda: int(os.getenv('BACKUP_COUNT', '3')))
    log_file: str = field(default_factory=lambda: os.getenv('LOG_FILE', 'generate_inventory.log'))
    log_level_name: str = field(default_factory=lambda: os.getenv('LOG_LEVEL', 'INFO'))

    # Organization
    organization: str = field(default_factory=lambda: os.getenv('ORGANIZATION', ''))

    # DB retry settings
    db_retry_count: int = field(default_factory=lambda: int(os.getenv('DB_RETRY_COUNT', '3')))
    db_retry_delay: int = field(default_factory=lambda: int(os.getenv('DB_RETRY_DELAY', '2')))  # seconds

    def __post_init__(self):
        """Parse derived fields after initialization."""
        self.log_level = getattr(logging, self.log_level_name.upper(), logging.INFO)

    def glpi_connect_kwargs(self) -> dict:
        """Build the kwargs dict for mysql.connector.connect() for the GLPI database."""
        kwargs = {
            'host': self.db_host,
            'port': self.db_port,
            'user': self.db_user,
            'password': self.db_password,
            'database': self.db_name,
        }
        if self.db_ssl_ca:
            kwargs['ssl_ca'] = self.db_ssl_ca
        if self.db_ssl_cert:
            kwargs['ssl_cert'] = self.db_ssl_cert
        if self.db_ssl_key:
            kwargs['ssl_key'] = self.db_ssl_key
        if self.db_ssl_verify_cert is not None:
            kwargs['ssl_verify_cert'] = self.db_ssl_verify_cert
        if self.db_ssl_verify_identity is not None:
            kwargs['ssl_verify_identity'] = self.db_ssl_verify_identity
        if self.db_use_pure is not None:
            kwargs['use_pure'] = self.db_use_pure
        return kwargs