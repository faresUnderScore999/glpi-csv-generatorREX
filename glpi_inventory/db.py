"""
Database connection and retry logic for GLPI Inventory Exporter.

Provides MySQL (GLPI) and PostgreSQL (Neon) connection functions with retry support.
"""

import logging
import sys
import time

import mysql.connector
import psycopg2

log = logging.getLogger('glpi_inventory')


def glpi_connect(config):
    """Connect to the GLPI (MySQL) database with retry logic."""
    kwargs = config.glpi_connect_kwargs()
    for attempt in range(1, config.db_retry_count + 1):
        try:
            conn = mysql.connector.connect(**kwargs)
            log.info(
                f"Connected to GLPI database {config.db_host}:{config.db_port}/{config.db_name}"
            )
            return conn
        except mysql.connector.Error as e:
            log.error(
                f"GLPI DB connection attempt {attempt}/{config.db_retry_count} failed: {e}"
            )
            if attempt < config.db_retry_count:
                log.info(f"Retrying in {config.db_retry_delay}s...")
                time.sleep(config.db_retry_delay)
            else:
                log.critical("All GLPI database connection attempts failed. Exiting.")
                sys.exit(1)


def pg_connect(config):
    """Connect to the Neon (PostgreSQL) database using the DSN."""
    if not config.pg_dsn:
        log.error("PG_DSN is not set. Cannot connect to PostgreSQL database.")
        return None
    try:
        conn = psycopg2.connect(config.pg_dsn, connect_timeout=config.pg_connect_timeout)
        log.info("Connected to Neon (PostgreSQL) database.")
        return conn
    except psycopg2.Error as e:
        log.error(f"Neon DB connection failed: {e}")
        return None