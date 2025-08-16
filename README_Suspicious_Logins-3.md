# Suspicious Logins — SQL Lab (SQLite + Python, Terminal-First)

This lab demonstrates a lightweight, terminal-first workflow to analyze **suspicious login activity** using a **synthetic database**. I loaded the dataset into **SQLite**, queried for suspicious logins and **logins from multiple locations**, and then used **Python (pandas)** to reproduce the queries and **export results to CSV** for reporting. Everything was done from the command line using **sqlite3**, **Python 3**, **pandas**, and a **virtual environment**.

---

## Objectives

- Practice **SQL for security analysis** on a synthetic dataset.
- Identify **suspicious logins** (e.g., repeated failures, unusually high IP diversity).
- Detect **logins from multiple locations** (per user, per day).
- Recreate/automate findings in **Python** and export to **CSV**.
- Build comfort working **entirely from the terminal**.

---

## Tech Stack & Tools

- **SQLite (sqlite3)** — local, file-based database for quick analysis.
- **Python 3** — scripting environment for automation.
- **pandas** — tabular queries and CSV export.
- **venv** — isolated Python environment (recommended best practice).
- Terminal-only workflow; IDEs/notebooks optional.

---

## Quick Start

> Replace filenames if your project uses different names. These commands assume a `logins.db` SQLite database and a `logins` table with at least:  
> `timestamp`, `username`, `ip_address`, and an optional `status` column (e.g., "success"/"failure").

### 1) SQLite: open the database
```bash
sqlite3 logins.db
```

Inside the SQLite shell, improve readability:
```sql
.headers on
.mode column
.timer on
```

### 2) Example SQL queries used

**A) Recent failed logins (simple triage)**
```sql
SELECT timestamp, username, ip_address
FROM logins
WHERE status = 'failure'
ORDER BY timestamp DESC
LIMIT 20;
```

**B) Users with > 2 unique IPs on the same day (multiple locations)**
```sql
SELECT username,
       date(timestamp) AS day,
       COUNT(DISTINCT ip_address) AS ip_count
FROM logins
GROUP BY username, day
HAVING ip_count > 2
ORDER BY ip_count DESC, day DESC;
```

**C) Noisiest IPs (high activity)**
```sql
SELECT ip_address, COUNT(*) AS attempts
FROM logins
GROUP BY ip_address
ORDER BY attempts DESC
LIMIT 10;
```

> Tip: If you track success/failure as integers (1/0) or booleans, adjust the `WHERE` clauses accordingly. If you also track geo info, you can expand B) into “impossible travel” by comparing countries/regions between consecutive logins for a user.

Exit SQLite:
```sql
.quit
```

---

## Optional: Python (pandas) for reporting

Create and activate a virtual environment, then install pandas:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install pandas
```

Sample Python script to run a query and **export CSV** (from project root):
```python
# file: export_suspicious_logins.py
import sqlite3, pandas as pd

DB = "logins.db"  # change if needed

con = sqlite3.connect(DB)

# Example: users with >2 unique IPs per day
q = """
SELECT username,
       date(timestamp) AS day,
       COUNT(DISTINCT ip_address) AS ip_count
FROM logins
GROUP BY username, day
HAVING ip_count > 2
ORDER BY ip_count DESC, day DESC;
"""
df = pd.read_sql_query(q, con)
con.close()

# Export to CSV for reporting
df.to_csv("outputs/suspicious_users_ip_diversity.csv", index=False)
print(f"Wrote outputs/suspicious_users_ip_diversity.csv with {len(df)} rows")
```

Run it:
```bash
mkdir -p outputs
python3 export_suspicious_logins.py
```

---

## Folder Structure (suggested)

```
suspicious_logins_project/
├─ logins.db                 # SQLite database (not tracked in git)
├─ export_suspicious_logins.py
├─ outputs/                  # CSV reports (git-ignored)
└─ README.md
```

**.gitignore (suggested):**
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

---

## What I Practiced & Learned

- Loading a **synthetic database** into SQLite for rapid, local analysis.
- Writing security-focused **SQL** to find suspicious patterns:
  - Recent failed logins
  - Multiple locations per user per day (distinct IP count)
  - Noisy IPs (activity volume)
- Using **pandas** to re-run queries, shape data, and **export** clean CSVs.
- Managing a **virtual environment** and working **entirely in the terminal**.
- Applying database and Python concepts in the context of **cybersecurity analysis**.

---

## Next Steps (Optional Enhancements)

- Add a **known-bad IPs** table and join to flag known threats.
- Script a **daily report** that runs all SQL queries and writes dated CSVs.
- Add basic **visualizations** (matplotlib) for trends per user/IP.
- Expand the schema with **user agent** and **geo** fields to detect “impossible travel.”
- Port the logic to a SIEM query language (e.g., **KQL**/**SPL**) to see how SQL thinking maps across tools.
