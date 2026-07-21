"""
Logging setup for GLPI Inventory Exporter.

Provides console logging and an optional rotating file handler with secure permissions.
"""

import logging
import os
import stat
import sys
from logging.handlers import RotatingFileHandler


def setup_logging(config):
    """Initialize and return a logger with console output."""
    logger = logging.getLogger('glpi_inventory')
    logger.setLevel(config.log_level)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(config.log_level)
    console.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(console)

    return logger


def setup_file_logging(logger, log_file):
    """Add a RotatingFileHandler to the logger with the resolved log file path."""
    try:
        fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(fh)
    except (IOError, PermissionError) as e:
        logger.warning(f"Could not create log file {log_file}: {e}")
    return logger


def set_secure_permissions(filepath):
    """Set file permissions to 0o600 (owner read/write only)."""
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        # Logger may not be available at this point; use print as fallback
        print(f"Warning: Could not set permissions 0o600 on {filepath}: {e}")