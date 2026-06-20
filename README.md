# Cybercrime-Scene Monitor

A self-hosted cybercrime-intelligence dashboard that scrapes breach/ransomware/marketplace sources, matches them against keyword rules, classifies incidents with an LLM, deduplicates them into cases, and surfaces everything through a live web UI.

## Features

- **Multi-source collection**: RSS, Mastodon, Nitter, Pastebin, HaveIBeenPwned, ransomware.live, HTML/Tor forums.
- **Keyword matching**: hot-reloadable YAML regex rules with priority, tags, and highlight spans.
- **LLM classification**: structured extraction of crime type, victim, actor, CVEs, IOCs, significance, and confidence. Supports OpenAI-compatible endpoints or the local `hermes` CLI.
- **Case correlation**: merges related raw observations into deduplicated incidents, including aggregated IoCs.
- **Algorithmic case cross-correlation**: links related cases by shared victim/actor/CVE/IoC overlap — surfaced as "Related cases".
- **CISA KEV enrichment**: flags cases that mention known-exploited vulnerabilities.
- **Autonomous self-improvement loop**: optional Hermes-agent research on significant cases (on a schedule or on-demand per case), self-healing that auto-applies validated fixes to `sources.yaml`, auto-prunes low-value/dead sources, and discovers new RSS/Atom sources — all gated by a relative investigation-value judgement (`sources/value.py`), informed by analyst feedback, with a full audit trail and revertible (`source_heal_proposals`, backed-up `sources.yaml`).
- **Analyst feedback**: mark cases/items useful, noise, or wrong-attribution — feeds both source value scoring and the autonomous loop's prompts.
- **Live dashboard**: FastAPI + vanilla-JS SPA with Server-Sent Events, Chart.js gauges, and a real-time subsystem status bar.
- **Advanced feed filtering**: filter items by time range, source, priority, crime type, actor, victim, CVE, IOC, tags, classification state, confidence, and cross-source cluster size. Cases are searchable by victim, actor, CVE, IoC, or timeframe.

## Quick start

```bash
# Install dependencies (uv recommended)
uv sync

# Copy example configs and edit them
 cp .env.example .env
 cp config/sources.yaml.example config/sources.yaml
 cp config/keywords.yaml.example config/keywords.yaml

# Run the server
uv run python -m cybercrime_monitor.main
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
src/cybercrime_monitor/
├── main.py              # uvicorn entry point
├── settings.py          # Pydantic settings from .env
├── db.py                # SQLite schema and queries
├── scheduler.py         # APScheduler wiring (collectors, LLM, correlation, KEV, retention, research, heal)
├── matcher.py           # Regex keyword matcher with hot reload
├── health.py            # In-memory per-source health registry
├── api/                 # FastAPI app, routes, SSE broadcaster, static SPA
├── collectors/          # One collector per source type
├── llm/                 # Structured extraction backend and job
├── pipeline/            # Case correlation / deduplication, algorithmic case cross-correlation
├── enrich/              # CVE extraction and CISA KEV catalog
├── research/            # Hermes-agent OSINT research, source self-healing, source discovery
├── sources/             # Investigation-value scoring and the sources.yaml writer
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
| Case cross-correlation | `CROSS_CORRELATE_INTERVAL_SECONDS` | Link related cases by shared victim/actor/CVE/IoC overlap. |
| Source value scoring | `SOURCE_VALUE_REFRESH_INTERVAL_SECONDS` | Recompute each source's investigation-value snapshot. |
| KEV refresh | `kev_refresh_interval_seconds` | Refresh CISA KEV catalog. |
| Retention | daily | Prune old non-critical items. |
| Hermes research | `HERMES_RESEARCH_INTERVAL_SECONDS` | Autonomous OSINT on significant (or explicitly re-queued) cases. |
| Hermes heal | `HERMES_HEAL_INTERVAL_SECONDS` | Investigate broken collectors, auto-apply validated fixes, prune low-value sources. |
| Hermes discover | `HERMES_DISCOVER_INTERVAL_SECONDS` | Search for and auto-add new RSS/Atom sources. |

## API

Public/read-only endpoints (no auth):

- `GET /healthz` — liveness/readiness.
- `GET /api/items` — feed items with filtering and pagination.
- `GET /api/stream` — SSE live feed.
- `GET /api/sources` — source health and schedule status.
- `GET /api/status` — unified subsystem status (scheduler, sources, classifier, correlator, KEV, research, heal).
- `GET /api/stats/*` — timeseries, priority, source, keyword, actor, case statistics.
- `GET /api/cases` — deduplicated incidents with filtering (victim/actor/CVE/IoC search, significance, crime type, KEV, timeframe).
- `GET /api/cases/{id}` — full case file: fields, IoCs, corroborating items, research run history, related cases.
- `GET /api/classifier/health` and `/api/classifier/recent`.
- `POST /api/feedback` — record a `useful`/`not_useful`/`noise`/`wrong_attribution` verdict on a case or item.

Admin-token gated:

- `GET/PUT /api/keywords` — view/edit keyword rules.
- `GET /api/heal/proposals` — self-healing/prune/discover proposal history and audit trail.
- `POST /api/cases/{id}/research` — force a deep-research pass on a case, bypassing the normal significance/cooldown gating.

## UI usage

- **Feed tab**: advanced filter sidebar, infinite-scroll item cards, live SSE updates, priority/classifier badges.
- **Cases tab**: top search/filter toolbar (victim, actor, CVE, IoC, timeframe) over a two-pane case rail + case-file detail view — IoCs, timeline, research status with a "Deep research" trigger, related cases, and feedback controls.
- **Keywords tab**: edit `keywords.yaml` directly (requires `ADMIN_TOKEN`).
- **Status bar**: real-time view of every background subsystem (including source self-healing and discovery); refreshes every 10 s and also reacts to SSE status events.

## Running under systemd

A unit file is provided in `systemd/cybercrime-monitor.service`. Copy/adapt it for your user and enable:

```bash
systemctl --user enable --now cybercrime-monitor.service
```

## License

MIT
