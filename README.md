# Suspicious Logins — SQL Lab (SQLite + Optional Python)

A beginner-friendly security analytics lab. You’ll triage synthetic authentication logs in SQLite, flag suspicious IPs (e.g., brute‑force/credential stuffing patterns), and optionally export results with a small Python helper.

---

## Project Goals
- Practice **SQL for security**: filtering, grouping, aggregations, and joins.
- Identify **noisy/suspicious IPs** and **targeted users**.
- Correlate logs with a tiny **threat intel list**.
- (Optional) Automate exports with **Python**.

---

## Data & Schema
**Tables**
- `auth_logs(event_id INTEGER PRIMARY KEY, timestamp TEXT, username TEXT, ip_address TEXT, success INTEGER)`  
  - `success`: 1 = success, 0 = failure
- `known_bad_ips(ip_address TEXT PRIMARY KEY, source TEXT, confidence INTEGER)`

**Files**
- `setup_sqlite.sql` — creates the tables and helpful indexes.
- `auth_logs.csv` — synthetic login events.
- `known_bad_ips.csv` — small threat feed.

> Note: The dataset is synthetic and safe to publish.

---

## Quick Start (SQLite)

From the project folder (e.g., `suspicious_logins_project`):

### 1) Create the database & tables
```bash
sqlite3 security_lab.db < setup_sqlite.sql
```

### 2) Import CSVs (choose ONE method)

**Method A — Header‑safe (works on any SQLite):**
```bash
tail -n +2 auth_logs.csv > auth_logs_nh.csv
tail -n +2 known_bad_ips.csv > known_bad_ips_nh.csv

sqlite3 security_lab.db <<'SQL'
.mode csv
.import auth_logs_nh.csv auth_logs
.import known_bad_ips_nh.csv known_bad_ips
SQL
```

**Method B — Newer SQLite (>= 3.32) supports `--skip 1`:**
```bash
sqlite3 security_lab.db <<'SQL'
.mode csv
.import --skip 1 auth_logs.csv auth_logs
.import --skip 1 known_bad_ips.csv known_bad_ips
SQL
```

### 3) Verify counts (inside sqlite3)
```sql
.headers on
.mode column
SELECT COUNT(*) AS rows_auth FROM auth_logs;
SELECT COUNT(*) AS rows_bad  FROM known_bad_ips;
```

---

## Mission Queries (run inside `sqlite3 security_lab.db`)

Set readable output once per session:
```sql
.headers on
.mode column
.timer on
```

**A) Recent failed logins (spot active brute‑force)**  
```sql
SELECT event_id, timestamp, username, ip_address
FROM auth_logs
WHERE success = 0
ORDER BY timestamp DESC
LIMIT 20;
```

**B) Users with most failures (identify weak/targeted accounts)**  
```sql
SELECT username, COUNT(*) AS failed_attempts
FROM auth_logs
WHERE success = 0
GROUP BY username
ORDER BY failed_attempts DESC;
```

**C) Noisiest IPs (find scanners/automation)**  
```sql
SELECT ip_address, COUNT(*) AS attempts
FROM auth_logs
GROUP BY ip_address
ORDER BY attempts DESC
LIMIT 10;
```

**D) Cross‑check with known bad list (prioritize triage)**  
```sql
SELECT a.ip_address,
       COUNT(*) AS total_attempts,
       kb.source,
       kb.confidence
FROM auth_logs AS a
LEFT JOIN known_bad_ips AS kb
  ON a.ip_address = kb.ip_address
GROUP BY a.ip_address
ORDER BY total_attempts DESC
LIMIT 10;
```
> Use `INNER JOIN` instead of `LEFT JOIN` to see **only** IPs present in the threat list.

---

## Optional: Export Results (no pandas)

Export any single query to CSV directly from the SQLite shell:
```sql
.once outputs/hits.csv
SELECT ip_address,
       SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS failed,
       COUNT(*) AS total
FROM auth_logs
GROUP BY ip_address
HAVING failed >= 5
ORDER BY failed DESC, total DESC;
```
Make sure the folder exists:
```bash
mkdir -p outputs
```

---

## Optional: Python Helper (simple, no argparse)

Save as `scripts/suspicious_logins.py`:
```python
#!/usr/bin/env python3
import os, sqlite3, csv, datetime as dt

DB = "security_lab.db"
OUT_DIR = "outputs"
os.makedirs(OUT_DIR, exist_ok=True)

since = (dt.datetime.now() - dt.timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")

q = """
SELECT ip_address,
       SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS failed,
       COUNT(*) AS total,
       COUNT(DISTINCT username) AS distinct_users
FROM auth_logs
WHERE timestamp >= ?
GROUP BY ip_address
HAVING failed >= 5
ORDER BY failed DESC, total DESC;
"""

con = sqlite3.connect(DB)
rows = con.execute(q, (since,)).fetchall()
con.close()

out_path = os.path.join(OUT_DIR, "suspicious_ips.csv")
with open(out_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ip_address","failed","total","distinct_users"])
    w.writerows(rows)

print(f"Wrote {len(rows)} rows to {out_path}")
```

Run it from the project root:
```bash
mkdir -p outputs scripts
chmod +x scripts/suspicious_logins.py
./scripts/suspicious_logins.py
```

### (Optional) Pandas version
If you prefer pandas, create a virtual env and install it:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install pandas
```
Then in Python:
```python
import sqlite3, pandas as pd
con = sqlite3.connect("security_lab.db")
df = pd.read_sql_query("SELECT * FROM auth_logs LIMIT 5;", con)
df.to_csv("outputs/sample.csv", index=False)
```

---

## Useful SQLite Shell Commands
```sql
.tables         -- list tables
.schema         -- show CREATE statements
.headers on     -- show column names
.mode column    -- pretty output
.mode csv       -- switch to CSV export mode
.once file.csv  -- write next query result to a file
.quit           -- exit sqlite
```

---

## .gitignore (suggested)
```
.venv/
*.db
*.db-*
outputs/*.csv
.DS_Store
__pycache__/
.ipynb_checkpoints/
.vscode/
.idea/
```
