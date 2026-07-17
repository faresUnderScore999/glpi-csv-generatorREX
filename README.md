# GLPI Inventory Script

**Version:** GLPI 11.0.8  
**Copyright:** (C) 2015-2026 Teclib' and contributors

---

## Overview

This script is designed to collect inventory information from GLPI, including installed software for each computer.

For every computer in the inventory, the script executes a separate database query to retrieve the list of installed software.

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