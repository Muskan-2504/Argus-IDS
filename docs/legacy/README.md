# Legacy — the original college project (preserved)

This folder is a **read-only snapshot** of the original *Intrusion Detection System* mini-project, built by **Muskan Gupta** for the 3rd-semester Database Management System Laboratory (academic year 2024–2025). It is kept here, unmodified, as the starting point that **Argus** rebuilds.

## What's here

| File | What it was |
|---|---|
| `index.html` | The entire frontend — UI, styling, and all "detection" logic in inline JavaScript. |
| `backend/db_config.php`, `login.php`, `submit_logs.php`, `fetch_details.php`, `reset_logs.php` | A PHP/MySQL backend intended for XAMPP. |
| `IDS proposal statement.docx` | Original proposal, including a 7-table relational schema. |
| `DMS project report.docx` | Final project report. |
| `Example Input Values.txt` | Sample timestamp logs used for the demo. |

## What it actually did (honest assessment)

- **Detection** ran entirely in the browser as three hard-coded heuristics on lines of pasted text: DoS = more than 5 lines; brute force = any duplicate line; port scan ≈ the same duplicate condition. It counted text, not network behavior.
- **The PHP backend was never connected** — `index.html` contains no `fetch`/AJAX calls, so the database layer was dead code.
- **"Authentication"** only hid one `<div>` and showed another. No password, no hashing, no roles — despite the report claiming salted hashes and RBAC.
- **Every PHP query was built by string-concatenating user input** → textbook SQL injection on all endpoints, with DB root credentials hard-coded and blank.
- The report claimed real-time visualization (Chart.js + D3), historical data, severity alerts, and SQL-injection/DDoS detection — none of which were implemented.

## Why keep it

It documents the honest before-state and makes the rebuild legible: Argus exists to take this prototype's *intent* and deliver it correctly and securely. The original schema in the proposal also informed the modern data model. See the root [`README.md`](../../README.md) and [`REBUILD_PLAN.md`](../REBUILD_PLAN.md).

> Nothing in this folder is imported or executed by Argus. It is reference only.
