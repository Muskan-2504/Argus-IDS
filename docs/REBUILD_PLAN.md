# Argus — Rebuild Plan

A ground-up rebuild of a college IDS prototype into a portfolio-grade, real-time threat-detection platform.

## Decisions

- **Stack:** Python 3.12+ / FastAPI (detection + API), React + TypeScript + Vite + Tailwind (dashboard), PostgreSQL 16 (SQLAlchemy 2.0 + Alembic), Redis, scikit-learn, Docker + GitHub Actions.
- **Scope:** "go all-in" — every tier below.

## Detection pipeline

`ingest → normalize → enrich → detect → score + MITRE map → persist + publish → triage`

- **Ingest:** file upload, `/ingest` API, and a replay generator. Parsers for `auth.log`, nginx/apache access logs, Suricata JSON.
- **Detect (three layers):**
  1. **Signature rules** — Sigma-style YAML (DoS, brute force, port scan, SQLi probes).
  2. **Statistical anomaly** — per-IP sliding-window rates, z-score / EWMA on request frequency.
  3. **ML** — Isolation Forest over extracted features, compared against the rules baseline.
- **Score + map:** severity scoring + MITRE ATT&CK technique per alert.
- **Enrich:** GeoIP (MaxMind GeoLite2) + reputation (AbuseIPDB), cached.
- **Deliver:** persist to Postgres, publish to Redis, stream to the dashboard over WebSocket; analysts triage (acknowledge / resolve / false-positive).

## Data model

`users` (Argon2 hash, role) · `log_sources` · `events` (normalized + JSONB raw, indexed on source_ip+timestamp) · `detection_rules` · `alerts` (severity, MITRE technique, status, score) · `ip_enrichment` (geo + reputation cache).

## Milestones

| Milestone | Deliverable |
|---|---|
| **M0** ✅ | Scaffold: repo, Docker, CI, data model, runnable API. |
| **M1** ✅ | Secure core: ingest API + parsers, Argon2 auth + RBAC, parameterized queries, initial migration. |
| **M2** | Rule engine: Sigma-style YAML rules, persisted alerts. |
| **M3** | Dashboard: React UI, alert list, charts, triage workflow. |
| **M4** | Real-time + enrichment: WebSocket feed, GeoIP/AbuseIPDB, D3 attack map. |
| **M5** | Intelligence: statistical + ML anomaly detection, MITRE mapping, severity. |
| **M6** | Demo polish: attack-replay harness, false-positive tuning loop, demo GIF. |

Each milestone is an independently demoable, committable unit.
