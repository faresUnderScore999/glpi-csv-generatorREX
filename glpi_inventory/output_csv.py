"""
CSV output module for GLPI Inventory Exporter.

Provides atomic CSV write with rotation and secure permission setting.
"""

import csv
import logging
import os
import shutil
import stat

log = logging.getLogger('glpi_inventory')


def set_secure_permissions(filepath):
    """Set file permissions to 0o600 (owner read/write only)."""
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        log.warning(f"Could not set permissions 0o600 on {filepath}: {e}")


def atomic_csv_write(rows, columns, output_file, backup_count):
    """Write rows to a CSV file atomically with rotating backups."""
    temp_file = output_file + '.tmp'
    try:
        with open(temp_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)

        set_secure_permissions(temp_file)

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