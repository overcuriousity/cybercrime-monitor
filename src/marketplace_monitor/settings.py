from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    db_path: Path = Path("data/items.db")
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    # Required to view/edit config/keywords.yaml via the API (GET/PUT /api/keywords).
    # GET leaks the investigation TARGET indicators (bank name/domain/IBAN) if unset
    # and reachable publicly; PUT writes regex straight to disk. Set via .env so the
    # admin UI keeps working while everything else stays open to the public dashboard.
    admin_token: str = ""
    tor_socks: str = "socks5h://127.0.0.1:9050"
    gotify_url: str = ""
    gotify_token: str = ""
    log_level: str = "INFO"
    sources_config: Path = Path("config/sources.yaml")
    keywords_config: Path = Path("config/keywords.yaml")
    # max items returned by /api/items
    items_page_size: int = 200

    # LLM classification layer (assigns real priority per item, flags false
    # positives) — see classifier/ package. "none" disables it entirely and
    # restores pre-classifier behavior (instant Gotify on regex 'critical',
    # no classifications table writes) with zero other config required.
    #
    # PRIVACY: item title/snippet text — which can include TARGET-tagged
    # investigation content from config/keywords.yaml — is sent to whatever
    # classifier_base_url points at for classification. The default (a local
    # LMStudio instance) keeps everything on-machine; pointing this at a
    # third-party API sends investigation content to that party.
    classifier_backend: str = "openai"  # "openai" | "none" (local model: future work)
    classifier_base_url: str = "http://127.0.0.1:1234/v1"  # LMStudio's default OpenAI-compatible port
    classifier_api_key: str = ""
    classifier_model: str = ""  # most local servers ignore this / use whatever's loaded
    classifier_batch_size: int = 10
    classifier_interval_seconds: int = 30
    # Generous: local CPU-bound inference can legitimately take a while
    # (prompt processing + generation), and a slow classify call has no
    # downside here — the job is already decoupled from ingest, and the
    # fallback sweep (below) backstops real critical alerts regardless.
    classifier_timeout_seconds: float = 90.0
    # If a regex-'critical' item is still unclassified after this many
    # minutes (classifier backend down/unreachable), alert on it anyway via
    # the fallback sweep — a downstream LLM outage must never silently
    # suppress a real critical alert.
    classifier_fallback_alert_minutes: int = 10
    # A false_positive=true verdict below this confidence is NOT trusted to
    # suppress the item — it stays visible (priority still applied) rather
    # than silently dropping out of the feed on a guess. A low-confidence
    # critical still alerts (never silently swallowed) but the Gotify
    # message flags the low confidence so it gets appropriate scrutiny.
    # 0.0 (default) preserves pre-threshold behavior: every verdict is trusted.
    classifier_min_confidence: float = 0.0

    # Items older than this are pruned (see db.py:prune_old_items, wired as a
    # daily job in scheduler.py) to keep the DB from growing unbounded.
    # Critical-priority items and anything matched by a "target"-tagged
    # keyword rule (config/keywords.yaml's TARGET section — the investigation
    # indicators) are NEVER pruned regardless of age, since those are
    # precisely the rows an investigation can't afford to silently lose.
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
