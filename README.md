# libsec

A vulnerability tracker for the web stack: PHP, Python, MySQL/MariaDB, PostgreSQL, nginx, Apache, Tomcat, OpenSSL, Docker, Laravel, Django and more — 50 products.
It collects from several sources, merges duplicates, ranks by urgency, writes short AI summaries and publishes a feed, RSS, JSON API and Telegram posts.

MVP: https://libsec.alid.in

```
cvelistV5 delta · OSV/GHSA · CISA KEV · EPSS · CVE API · nginx.org
        │  collectors (own interval each, ETag/deltas)
        ▼
raw_items ─► facts (per source) ─► vulns (merged, aliases) ─► events
        │  product catalog filter, rule-based priority
        ▼
AI analysis (strict JSON schema, versions verified in code)
        ▼
site · RSS · /api/v1 · Telegram queue (urgent now, rest as daily digest)
```

## Layout
- `app/libsec/catalog.py` — tracked products and how each is recognised (CNA names, CPE, distro packages, OSV packages, KEV).
- `app/libsec/collectors/` — one module per source (`NAME`, `INTERVAL`, `run()`).
- `app/libsec/normalize.py`, `pipeline.py` — parsing, dedup, recompute, events.
- `app/libsec/ai.py` — AI analysis (Anthropic API; local `claude -p` fallback).
- `app/libsec/tg.py` — Telegram queue and rules.
- `app/libsec/worker.py` — scheduler: `python -m libsec.worker [once [source…] | reparse]`.
- `app/libsec/web.py`, `app/templates/` — the site, RSS and API.
- `deploy/` — systemd units `libsec` (web) and `libsec-worker`, nginx config.
- `docs/brief.md` — the original brief; `docs/decisions.md` — decisions made for the MVP.

## Run
```bash
python3 -m venv ~/venvs/libsec && ~/venvs/libsec/bin/pip install -r app/requirements.txt
cd app && ~/venvs/libsec/bin/python -m libsec.worker once      # collect everything once
~/venvs/libsec/bin/uvicorn libsec.web:app --port 8795          # site
~/venvs/libsec/bin/python -m tests.test_core                   # parser tests on snapshots
```

Data is stored in `data/libsec.db` (SQLite, not in git).
