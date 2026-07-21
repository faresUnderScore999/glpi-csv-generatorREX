# GLPI Inventory Script

**Version:** GLPI 11.0.8  
**Copyright:** (C) 2015-2026 Teclib' and contributors

---

## Overview

This script collects inventory information from GLPI (computers + network equipment) and exports them to:
- A **CSV file** (`assets_inventory.csv`)
- A **PostgreSQL (Neon) database** (optional)

The codebase has been refactored into a modular `glpi_inventory` package for better organization and maintainability.

---

## Quick Start

### Prerequisites

```bash
pip install mysql-connector-python psycopg2-binary python-dotenv
```

### Setup

1. Copy the example environment file and edit it with your database credentials:
   ```bash
   cp .env.exemple .env
   ```

2. Edit `.env` to configure:
   - **GLPI (MySQL)** connection: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
   - **Neon (PostgreSQL)** connection: `PG_DSN` (required for `postgresql` or `both` mode)
   - **Output mode**: `OUTPUT_MODE=csv` (default), `postgresql`, or `both`
   - **Output file**: `OUTPUT_FILE=assets_inventory.csv`

### Run

You can run the exporter using either command:

```bash
# Method 1 — Original entry point (backward compatible)
python generate_inventory.py

# Method 2 — Package module (recommended)
python -m glpi_inventory
```

---

## Configuration (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `172.17.0.1` | GLPI MySQL host |
| `DB_PORT` | `3306` | GLPI MySQL port |
| `DB_USER` | `glpi` | GLPI MySQL user |
| `DB_PASSWORD` | `glpi` | GLPI MySQL password |
| `DB_NAME` | `glpi` | GLPI MySQL database |
| `PG_DSN` | — | Neon PostgreSQL DSN (e.g. `postgresql://user:pass@host/db`) |
| `OUTPUT_MODE` | `csv` | Output mode: `csv`, `postgresql`, or `both` |
| `OUTPUT_FILE` | `assets_inventory.csv` | CSV output file path |
| `BACKUP_COUNT` | `3` | Number of CSV backups to keep |
| `LOG_FILE` | `generate_inventory.log` | Log file path |
| `LOG_LEVEL` | `INFO` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `DB_RETRY_COUNT` | `3` | Number of connection retries |
| `DB_RETRY_DELAY` | `2` | Seconds between retries |
| `EXCLUDED_ASSETS` | — | Comma-separated hostnames to skip |

---

## Project Structure

```
├── generate_inventory.py          # Thin entry point (backward compatible)
├── glpi_inventory/                # Modular package
│   ├── __init__.py                # Package marker + version
│   ├── __main__.py                # `python -m glpi_inventory` entry
│   ├── config.py                  # Configuration loading + typed Config dataclass
│   ├── logger.py                  # Console + file logging setup
│   ├── db.py                      # MySQL (GLPI) + PostgreSQL (Neon) connections
│   ├── queries.py                 # SQL queries + retry-aware executor
│   ├── mapping.py                 # Status/criticality mapping + asset classification
│   ├── parsers.py                 # Raw value preservation + sysDescr OS parser
│   ├── output_csv.py              # Atomic CSV write with rotation
│   ├── output_pg.py               # PostgreSQL upsert logic
│   └── main.py                    # Orchestrator (main function)
├── .env                           # Your configuration
├── .env.exemple                   # Example configuration
└── README.md                      # This file
```

---

## Performance Considerations

### Database Query Behavior

- The script performs **one query per computer** to fetch installed software.
- The current implementation uses `fetchall()` to retrieve query results.

⚠️ **Warning:**  
`fetchall()` loads all returned rows into memory. For large inventories, this can lead to high memory consumption and possible memory exhaustion.

---

## Inventory Size Capacity

| Inventory Size | Can It Handle It? | Expected Runtime | Risk Level |
|----------------|-------------------|------------------|------------|
| **< 500 devices** | ✅ Handles easily | < 30 seconds | 🟢 Low |
| **500 – 2,000 devices** | ✅ Works but slower | 2 – 5 minutes | 🟡 Medium |
| **2,000 – 10,000 devices** | ⚠️ May struggle | 10 – 30 minutes | 🟠 High |
| **> 10,000 devices** | ❌ Likely to crash or timeout | Could exceed database `wait_timeout` | 🔴 Critical |

---

## Recommendations for Large Inventories

For environments with more than 2,000 devices, consider the following optimizations:

- Replace `fetchall()` with cursor-based iteration (`fetchone()` / streaming).
- Avoid executing one query per computer (N+1 query problem).
- Use batch queries to retrieve software information.
- Add database indexes on frequently queried columns.
- Process inventories in chunks (pagination).
- Increase database timeout values if required.

---

## Known Limitations

| Limitation | Impact |
|------------|--------|
| One database query per device | Slower execution for large inventories |
| Full result loading with `fetchall()` | Higher memory consumption |
| No batch processing | Reduced scalability |

---

## Supported Environment

- **GLPI Version:** 11.0.8
- **Database:** Compatible with GLPI supported databases
- **Recommended Usage:** Small to medium inventories (< 2,000 devices)

---

## Future Improvements

- [ ] Implement streaming database fetch.
- [ ] Replace N+1 queries with optimized joins.
- [ ] Add batch processing support.
- [ ] Add progress tracking for long-running inventories.
- [ ] Add error handling and retry mechanisms.