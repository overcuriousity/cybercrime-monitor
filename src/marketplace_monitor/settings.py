from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    db_path: Path = Path("data/items.db")
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    # Required to view/edit config/keywords.yaml via the API (GET/PUT /api/keywords).
    # Set via .env so the admin UI keeps working while everything else stays open
    # to the public dashboard.
    admin_token: str = ""
    tor_socks: str = "socks5h://127.0.0.1:9050"
    gotify_url: str = ""
    gotify_token: str = ""
    log_level: str = "INFO"
    sources_config: Path = Path("config/sources.yaml")
    keywords_config: Path = Path("config/keywords.yaml")
    # max items returned by /api/items
    items_page_size: int = 200

    # ── LLM extraction layer ────────────────────────────────────────────────
    # Structured-field extraction (crime type, victim, attribution, CVEs,
    # significance) per item — see llm/ package. "none" disables it entirely
    # and restores pre-extraction behavior (instant Gotify on regex
    # 'critical', no extractions table writes) with zero other config
    # required.
    #
    # "hermes_cli" routes extraction/dedup through the locally-installed
    # hermes-agent CLI instead of an HTTP endpoint (see hermes_* settings
    # below and llm/backend.py's module docstring) — useful when there's no
    # separate OpenAI-compatible server running but `hermes` already works.
    # llm_base_url/llm_api_key/llm_model are ignored in this mode; the model
    # used is whatever `hermes model` is configured to (or hermes_model below
    # to override per-call).
    #
    # PRIVACY: item title/snippet text is sent to whatever backend handles
    # it — llm_base_url for "openai", or hermes-agent's configured
    # provider for "hermes_cli" (e.g. a cloud API like Kimi/OpenRouter, not
    # necessarily local — check `hermes status`). The "openai" default (a
    # local LMStudio/vLLM instance) keeps everything on-machine.
    llm_backend: str = "openai"  # "openai" | "hermes_cli" | "none"
    llm_base_url: str = "http://127.0.0.1:1234/v1"  # LMStudio's default OpenAI-compatible port
    llm_api_key: str = ""
    llm_model: str = ""  # most local servers ignore this / use whatever's loaded
    llm_batch_size: int = 10
    llm_interval_seconds: int = 30
    # Generous: local CPU-bound inference can legitimately take a while
    # (prompt processing + generation), and a slow extract call has no
    # downside here — the job is already decoupled from ingest, and the
    # fallback sweep (below) backstops real critical alerts regardless.
    llm_timeout_seconds: float = 90.0
    # If a regex-'critical' item is still unextracted after this many
    # minutes (LLM backend down/unreachable), alert on it anyway via the
    # fallback sweep — a downstream LLM outage must never silently suppress
    # a real critical alert.
    llm_fallback_alert_minutes: int = 10
    # A false_positive=true verdict below this confidence is NOT trusted to
    # suppress the item — it stays visible (priority still applied) rather
    # than silently dropping out of the feed on a guess. A low-confidence
    # critical still alerts (never silently swallowed) but the Gotify
    # message flags the low confidence so it gets appropriate scrutiny.
    # 0.0 (default) preserves pre-threshold behavior: every verdict is trusted.
    llm_min_confidence: float = 0.0

    # Semantic dedup → case correlation (pipeline/correlate.py) — runs on its
    # own interval, decoupled from extraction, so a slow merge-adjudication
    # call never blocks either ingest or extraction.
    correlate_interval_seconds: int = 45

    # ── hermes-agent integration ────────────────────────────────────────────
    # hermes-agent (Nous Research's self-improving agent CLI — NOT the Hermes
    # model) drives the two genuinely agentic roles: autonomous OSINT research
    # on cases (research/agent.py) and self-healing of broken collectors
    # (research/heal.py). Both shell out to the locally-installed `hermes`
    # binary headless (`hermes -z "<prompt>" -t <toolsets>`) via
    # hermes/runner.py — see that module's docstring for the verified
    # one-shot contract. Bulk per-item extraction does NOT go through Hermes
    # (too slow/expensive for volume); it uses llm_backend above, optionally
    # pointed at `hermes proxy`'s OpenAI-compatible endpoint if you want the
    # same model/account for both paths.
    hermes_bin: str = "hermes"
    hermes_model: str = ""  # empty = whatever Hermes' own `hermes model` default is
    hermes_toolsets: str = "web,browser"
    hermes_timeout_seconds: float = 300.0
    # 0 disables both agentic jobs entirely (research_runs/source-healing
    # never dispatch) without touching llm_backend.
    hermes_research_interval_seconds: int = 900
    hermes_heal_interval_seconds: int = 3600
    # A source must accumulate this many consecutive collector errors before
    # the self-healing job will spend a Hermes run investigating it.
    hermes_heal_error_threshold: int = 5

    # CISA KEV (Known Exploited Vulnerabilities) catalog — refreshed daily
    # into the kev_catalog table; see enrich/kev.py.
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    kev_refresh_interval_seconds: int = 86400

    # Items older than this are pruned (see db.py:prune_old_items, wired as a
    # daily job in scheduler.py) to keep the DB from growing unbounded.
    # Effective-critical cases/items are NEVER pruned regardless of age.
    retention_days: int = 90

    # ── Public-dashboard DoS resistance ─────────────────────────────────────
    # The dashboard is meant for one analyst's own browser tabs but is
    # commonly reachable publicly (see admin_token's docstring above) —
    # these bound the two resources that scale with concurrent
    # clients/requests instead of being fixed-cost.
    sse_max_subscribers: int = 50
    # Per-IP token bucket on /api/* (see api/app.py's rate_limit_middleware).
    # 0 disables rate limiting entirely.
    rate_limit_per_minute: int = 120


settings = Settings()
