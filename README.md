# Cybercrime-Scene Monitor

A self-hosted cybercrime-intelligence dashboard that scrapes breach/ransomware/marketplace sources, matches them against keyword rules, classifies incidents with an LLM, deduplicates them into cases, and surfaces everything through a live web UI.

## Features

- **Multi-source collection**: RSS, Mastodon, Nitter, Pastebin, HaveIBeenPwned, ransomware.live, HTML/Tor forums.
- **Keyword matching**: hot-reloadable YAML regex rules with priority, tags, and highlight spans.
- **LLM classification**: structured extraction of crime type, victim, actor, CVEs, IOCs, significance, and confidence. Supports OpenAI-compatible endpoints or the local `hermes` CLI.
- **Case correlation**: merges related raw observations into deduplicated incidents.
- **CISA KEV enrichment**: flags cases that mention known-exploited vulnerabilities.
- **Autonomous OSINT**: optional Hermes-agent research on significant cases and self-healing proposals for broken collectors.
- **Live dashboard**: FastAPI + vanilla-JS SPA with Server-Sent Events, Chart.js gauges, and a real-time subsystem status bar.
- **Advanced feed filtering**: filter items by time range, source, priority, crime type, actor, victim, CVE, IOC, tags, classification state, confidence, and cross-source cluster size.

## Quick start

```bash
# Install dependencies (uv recommended)
uv sync

# Copy example configs and edit them
 cp .env.example .env
 cp config/sources.yaml.example config/sources.yaml
 cp config/keywords.yaml.example config.keywords.yaml

# Run the server
uv run python -m marketplace_monitor.main
```

Open `http://127.0.0.1:8000`.

## Configuration

Configuration lives in three places:

| File | Purpose |
|---|---|
| `.env` | Runtime settings: bind host/port, DB path, LLM backend, Gotify, retention, rate limits. |
| `config/sources.yaml` | Data sources: type, URL, interval, credentials, selectors. |
| `config/keywords.yaml` | Regex keyword rules with priority (`info`/`warn`/`critical`) and tags. |

See `.env.example` and `config/*.yaml.example` for documented templates.

## Architecture

```
src/marketplace_monitor/
├── main.py              # uvicorn entry point
├── settings.py          # Pydantic settings from .env
├── db.py                # SQLite schema and queries
├── scheduler.py         # APScheduler wiring (collectors, LLM, correlation, KEV, retention, research, heal)
├── matcher.py           # Regex keyword matcher with hot reload
├── health.py            # In-memory per-source health registry
├── api/                 # FastAPI app, routes, SSE broadcaster, static SPA
├── collectors/          # One collector per source type
├── llm/                 # Structured extraction backend and job
├── pipeline/            # Case correlation / deduplication
├── enrich/              # CVE extraction and CISA KEV catalog
├── research/            # Hermes-agent OSINT research and source self-healing
└── hermes/              # `hermes` CLI wrapper
```

Data is stored in `data/items.db` (SQLite with WAL mode).

## Background jobs

The scheduler runs all subsystems concurrently:

| Job | Interval | What it does |
|---|---|---|
| Per-source collectors | `sources.yaml` | Fetch new posts/items, dedupe, match keywords, store, broadcast via SSE. |
| LLM extraction | `LLM_INTERVAL_SECONDS` | Classify unextracted items, fire Gotify critical alerts, fallback sweep. |
| Case correlation | `CORRELATE_INTERVAL_SECONDS` | Merge extracted items into deduplicated cases. |
| KEV refresh | `kev_refresh_interval_seconds` | Refresh CISA KEV catalog. |
| Retention | daily | Prune old non-critical items. |
| Hermes research | `HERMES_RESEARCH_INTERVAL_SECONDS` | Autonomous OSINT on significant cases. |
| Hermes heal | `HERMES_HEAL_INTERVAL_SECONDS` | Investigate broken collectors and propose fixes. |

## API

Public/read-only endpoints (no auth):

- `GET /healthz` — liveness/readiness.
- `GET /api/items` — feed items with filtering and pagination.
- `GET /api/stream` — SSE live feed.
- `GET /api/sources` — source health and schedule status.
- `GET /api/status` — unified subsystem status (scheduler, sources, classifier, correlator, KEV, research, heal).
- `GET /api/stats/*` — timeseries, priority, source, keyword, actor, case statistics.
- `GET /api/cases` — deduplicated incidents with filtering.
- `GET /api/classifier/health` and `/api/classifier/recent`.

Admin-token gated:

- `GET/PUT /api/keywords` — view/edit keyword rules.
- `GET /api/heal/proposals` — self-healing proposals.

## UI usage

- **Feed tab**: advanced filter sidebar, infinite-scroll item cards, live SSE updates, priority/classifier badges.
- **Cases tab**: deduplicated incidents, KEV flags, crime-type filters, detail pane with corroborating sources.
- **Keywords tab**: edit `keywords.yaml` directly (requires `ADMIN_TOKEN`).
- **Status bar**: real-time view of every background subsystem; refreshes every 10 s and also reacts to SSE status events.

## Running under systemd

A unit file is provided in `systemd/marketplace-monitor.service`. Copy/adapt it for your user and enable:

```bash
systemctl --user enable --now marketplace-monitor.service
```

## License

MIT
