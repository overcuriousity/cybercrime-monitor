from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    db_path: Path = Path("data/items.db")
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    # Required for admin-gated API routes (force re-research, view filtered
    # items, the targeted-investigation trigger). Set via .env so the admin
    # UI keeps working while everything else stays open to the public
    # dashboard.
    admin_token: str = ""
    tor_socks: str = "socks5h://127.0.0.1:9050"
    gotify_url: str = ""
    gotify_token: str = ""
    log_level: str = "INFO"
    sources_config: Path = Path("config/sources.yaml")
    # max items returned by /api/items
    items_page_size: int = 200

    # ── LLM extraction layer ────────────────────────────────────────────────
    # Structured-field extraction (crime type, victim, attribution, CVEs,
    # significance) per item — see llm/ package. "none" disables it entirely
    # (no extractions table writes, no alerting) with zero other config
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
    # When llm_backend="openai" and that endpoint is simply not reachable
    # (connection refused/timeout — no dedicated LLM server running), and the
    # `hermes` CLI is already installed/on PATH, transparently route
    # extraction through it instead (see llm/backend.py's _BackendUnreachable
    # handling) rather than leaving every item permanently unextracted and
    # retrying a dead endpoint forever. Does NOT apply when llm_backend is
    # explicitly set to "hermes_cli" or "none" — those are deliberate
    # choices, not gaps to paper over. Set false to keep the old
    # retry-forever-against-openai behavior.
    llm_auto_fallback_to_hermes: bool = True
    # How long to keep using the hermes fallback before re-probing the
    # openai endpoint (so a now-restarted LMStudio/vLLM gets used again
    # without a process restart, but a permanently-absent one doesn't waste
    # a request retrying it every single batch).
    llm_fallback_cooldown_seconds: int = 300
    # Generous: local CPU-bound inference can legitimately take a while
    # (prompt processing + generation), and a slow extract call has no
    # downside here — the job is already decoupled from ingest.
    llm_timeout_seconds: float = 90.0
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
    # Algorithmic (non-LLM) case-to-case relationship scan
    # (pipeline/cross_correlate.py) — separate from the above, which
    # dedupes raw items into cases; this links already-distinct cases that
    # share victim/actor/CVE/IoC overlap, surfaced as "Related cases".
    cross_correlate_interval_seconds: int = 600
    # Cross-correlation → escalation (quick win C2) — when a new high-score
    # case_link attaches a case to a more-severe peer (confirmed status,
    # critical significance, or in_kev), nudge the less-severe case toward
    # research (db.nudge_case) and, optionally, bump its significance one
    # rung. min_score is deliberately well above _MIN_LINK_SCORE (0.3) so a
    # single weak link can't trigger escalation. The significance bump
    # defaults off — boosting toward research is the conservative default;
    # auto-raising significance is reversible (run_significance_decay) but
    # still gated separately until proven out.
    cross_correlate_escalation_enabled: bool = True
    cross_correlate_escalation_min_score: float = 0.6
    cross_correlate_escalation_boost: float = 2.0
    cross_correlate_escalation_bump_enabled: bool = False

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
    # Browsing-heavy research/heal/discover runs (multiple searches + page
    # fetches) routinely take several minutes; 300s was observed timing out
    # legitimate runs mid-investigation, not just hung ones.
    hermes_timeout_seconds: float = 900.0
    # Bounded in-process retry for hermes/runner.py's clearly-transient
    # failures (a rate-limited/empty-response provider hop, not a real
    # outage) — see runner.py's _is_transient. Does NOT cover timeouts (too
    # expensive to retry a 900s+ run in-process); those still fall through
    # to the caller's own scheduler/cooldown. 1 retry is enough to ride out
    # a single bad provider hop in a fallback chain without doubling the
    # cost of a sustained outage.
    hermes_max_retries: int = 1
    hermes_retry_backoff_seconds: float = 5.0
    # Global cap on concurrently-running hermes-agent subprocesses, shared
    # across research/agent.py, research/investigate.py and research/heal.py
    # (all three funnel through hermes/runner.py's run_agent) — they all hit
    # the same primary backend, so this is the one knob that actually
    # protects it regardless of which job is dispatching. Sized for the
    # NVIDIA NIM primary's published limits (2026-06-21): 0.83 req/s (~50/min)
    # and 1M tokens/min. Tokens are not the binding constraint — a research
    # turn runs a few thousand tokens, nowhere near 1M/min even at this
    # concurrency. Requests/sec is: each concurrent run is a multi-turn
    # hermes-agent loop (web search + page fetches between LLM calls), not a
    # tight request loop, so observed per-run request rate is well under
    # 1 req/s; 2 concurrent runs keeps sustained aggregate load under the
    # 0.83 req/s ceiling with headroom for bursts, while still being a large
    # improvement over the previous fully-serial (1 at a time) dispatch.
    # Raise cautiously — and only after confirming actual request-rate
    # headroom — since exceeding the cap just trades research throughput for
    # 429s that burn the fallback_providers chain (kimi-coding -> devstral-2512)
    # instead.
    hermes_max_concurrent_runs: int = 2
    # Real (measured) token burn-rate tracking — see db.token_usage and
    # hermes/usage_ingest.py. hermes-agent measures its own token usage per
    # session in ~/.hermes/state.db (not estimated); this job copies that
    # into our own db on a poll so it can be queried/aggregated alongside the
    # direct-llm usage llm/backend.py logs per-call. 0 disables the ingester
    # — hermes-agent rows simply never appear in /api/tokens, direct-llm
    # usage is unaffected.
    hermes_state_db_path: Path = Path("~/.hermes/state.db")
    token_ingest_interval_seconds: int = 30
    # Averaging window for the headline tokens/hour figure on the Activity
    # tab — wide enough to smooth over a single burst/idle tick, narrow
    # enough to reflect "what's happening right now" rather than a daily
    # average.
    burn_rate_window_seconds: int = 3600
    # 0 disables this job only (research_runs never dispatch) without
    # touching llm_backend. heal/investigate/discover are gated by their own
    # *_interval_seconds settings below, independently.
    hermes_research_interval_seconds: int = 120
    # How many eligible cases get pulled per tick and dispatched concurrently
    # (bounded by hermes_max_concurrent_runs, not run in lockstep with this
    # number) — see research/agent.py's run_research_batch. Larger than the
    # concurrency cap on purpose: while hermes_max_concurrent_runs workers are
    # busy, the rest of the batch just queues for the next free slot within
    # the same tick, so the job stays continuously busy instead of going idle
    # between short ticks.
    hermes_research_batch_size: int = 8
    # A *failed* research run (timeout, hermes error, malformed response —
    # see research.agent's docstring on db.get_cases_needing_research) gets
    # retried much sooner than a successful one: 24h of "don't bother, we
    # already have an answer" makes no sense for "we never got an answer."
    # Without this, a backend-side outage (e.g. a provider rejecting the
    # request shape — see ops notes from 2026-06-21) silently locks every
    # case it touches out of research for a full day, even after the
    # backend recovers. Short enough to self-heal within hours of a
    # transient/upstream issue, long enough that one chronically-failing
    # case (bad encoding, truly unresearchable) can't monopolize every
    # tick — at hermes_max_concurrent_runs=2, a 2h floor still caps one stuck
    # case to a handful of attempts/day, not one per tick.
    research_failure_retry_hours: int = 2
    # Significance-scaled re-research cadence — this is the lever that makes
    # token spend track case importance instead of a flat cooldown (see
    # db.get_cases_needing_research). A case at "info" is researched exactly
    # ONCE (no interval — it's eligible iff it has zero completed runs); a
    # "warn" case is re-researched on research_warn_interval_seconds; a
    # "critical" case (a clear victim with an ONGOING crime) is re-researched
    # on the much shorter research_critical_interval_seconds, since fresh
    # info matters most while a crime is still unfolding.
    research_critical_interval_seconds: int = 86400  # daily
    research_warn_interval_seconds: int = 604800  # weekly
    # Generalized nudge primitive (agentic-coordination foundation F1, see
    # db.nudge_case) — a backstop eligibility floor for cases.priority_boost
    # in db._research_eligibility_sql, for nudgers that raise the boost
    # without also forcing research_requested_at. Most current nudgers
    # (cross-correlation escalation, feedback re-analysis) set both, so this
    # floor is rarely the deciding factor — it's a safety net.
    research_priority_boost_floor: float = 1.0
    # Per-tick geometric decay applied to priority_boost on the
    # significance-decay job's cadence (db._decay_priority_boost) — keeps an
    # unconsumed nudge from pinning a case at the front of the research
    # queue forever. 1.0 disables decay (boost only clears when research
    # completes/fails the case).
    priority_boost_decay_factor: float = 0.5
    # Mechanical staleness safety-net (db.run_significance_decay), independent
    # of any research pass: a case with no new corroborating item AND no
    # completed research run within this window is treated as no longer
    # "ongoing" and is capped down a level (critical->warn->info). Only
    # applies once research_age exceeds this window too, so an
    # actively-researched critical case (daily cadence, well within this
    # window) is never touched by decay — the researcher's own verdict is
    # what governs it.
    research_stale_window_seconds: int = 604800  # 7 days
    # 0 disables the decay job entirely.
    significance_decay_interval_seconds: int = 86400
    hermes_heal_interval_seconds: int = 3600
    # Investigator-triggered targeted research (POST /api/investigations,
    # research/investigate.py) — drains queued investigations. The interval
    # is just a safety net: the endpoint nudges the job to run immediately on
    # submit, same pattern as the case-research force-trigger. 0 disables the
    # job (investigations stay queued and are never picked up).
    hermes_investigate_interval_seconds: int = 900
    # An investigation's findings are only integrated (case + items + source
    # candidates) when Hermes reports found=true AND at least this much
    # confidence — "only if it DID really find something" per design intent.
    investigate_min_confidence: float = 0.5
    # A *transient* investigation failure (see runner.py's _is_transient —
    # a rate-limited/empty-response provider hop, not a real outage) is
    # re-queued instead of going terminal, same reasoning as
    # research_failure_retry_hours but on a much shorter cooldown:
    # investigations are user-initiated and time-sensitive (the investigator
    # is often waiting on the result), so minutes rather than hours is
    # appropriate. Capped at investigate_max_attempts so a permanently
    # broken brief can't loop forever.
    investigate_max_attempts: int = 3
    investigate_failure_retry_minutes: int = 15
    # A source must accumulate this many consecutive collector errors before
    # the self-healing job will spend a Hermes run investigating it.
    hermes_heal_error_threshold: int = 5
    # A scrape-access source (sources/value.py's access_for) must accumulate
    # this many consecutive *successful-but-empty* fetches (health.py's
    # consecutive_empty — 200 OK, 0 items parsed) before it's treated as
    # "structurally empty"/degraded: investigated by heal, and eligible for
    # prune if heal can't fix it. Keep in sync with app.js's
    # _EMPTY_STREAK_THRESHOLD, which drives the same "degraded" dashboard dot.
    source_empty_streak_threshold: int = 5
    # Truly agentic self-improvement loop (research/heal.py + writer.py):
    # validated heal fixes are written straight to sources.yaml and the
    # collector is live-rescheduled, low-value sources are auto-disabled/
    # removed, and a separate discovery job searches for brand-new sources
    # to add — all gated by sources/value.py's relative investigation-value
    # judgement (see that module's docstring), not a static confidence
    # number. Set false to fall back to the old advisory-only behavior
    # (proposals are still logged to source_heal_proposals either way).
    source_autoapply_enabled: bool = True
    # 0 disables the discovery job entirely (independent of hermes_heal_*).
    hermes_discover_interval_seconds: int = 21600  # 6h — discovery is a slow, exploratory Hermes run
    # Research → discovery hand-off (quick win B1) — discovery additionally
    # mines domains cited in recent completed research_runs.sources as
    # pre-warmed candidates (the research agent already vouched for their
    # relevance), run through the same RSS-probe/forum-scrape validation as
    # any other candidate. False disables the hand-off; discovery still runs
    # its normal Hermes-proposed search.
    research_handoff_enabled: bool = True
    # A newly-discovered source is tagged "probationary" and given this many
    # days to prove itself (sources/value.py needs real run history before
    # it can judge a source) before the prune path is allowed to act on it.
    source_probation_days: int = 7
    # How long a source stays merely "disabled" before remove() deletes the
    # entry outright — gives a human a window to notice and override an
    # autonomous disable before it's gone from sources.yaml entirely. Also
    # applies to hand-disabled sources once the prune pass starts tracking
    # them (see research/heal.py's _maybe_remove_source) — kept short so
    # stale `# needs:` entries don't linger indefinitely, since heal already
    # gets a recovery attempt every _HEAL_COOLDOWN_HOURS before this elapses.
    source_prune_grace_days: int = 5
    source_value_refresh_interval_seconds: int = 1800
    # Cross-case actor knowledge base refresh (agentic-coordination
    # foundation F3, pipeline/actor_profiles.py) — mirrors
    # source_value_refresh_interval_seconds' cadence/kill-switch shape. 0
    # disables the job; get_actor_profile then only returns whatever was
    # last materialized (or 404s if it never ran).
    actor_profiles_refresh_interval_seconds: int = 1800
    # Value-driven adaptive polling (quick win A1) — after each
    # _value_refresh tick, a source's *effective* poll interval is derived
    # from its cached sources/value.py classification instead of staying
    # pinned to sources.yaml's static interval_seconds forever: "valuable"
    # sources poll faster, "marginal" ones slower, clamped to
    # [adaptive_poll_min_seconds, adaptive_poll_max_seconds]. "dead" sources
    # are left alone here — they're heal/prune's job, not a polling-speed
    # problem. False disables the whole block (sources keep their static
    # configured interval).
    adaptive_polling_enabled: bool = True
    adaptive_poll_valuable_factor: float = 0.5
    adaptive_poll_marginal_factor: float = 2.0
    adaptive_poll_min_seconds: int = 300
    adaptive_poll_max_seconds: int = 7200
    # Target size of the managed source population — discovery and pruning
    # both steer toward this number instead of running as independent,
    # unbounded loops (see research/discover.py's gap-based batch sizing and
    # research/heal.py's _prune_pass overage trim). A deadband around the
    # target avoids thrashing (one source added/removed every cycle).
    source_target_count: int = 25
    source_target_band: int = 3
    # 0 disables the evaluator job. A periodic Hermes agent (research/
    # evaluator.py) that reads a case's items like a human analyst would and
    # writes its own feedback rows (origin="agent") — gives source scoring an
    # actionable signal even when no one has clicked a feedback button.
    hermes_evaluator_interval_seconds: int = 7200
    evaluator_items_per_run: int = 12
    # Agent-authored feedback counts toward source scoring at this fraction
    # of a human verdict's weight (sources/value.py._component_feedback) —
    # synthetic signal is useful but shouldn't outrank a real analyst's call.
    feedback_agent_weight: float = 0.5
    # Feedback-triggered re-analysis (quick win C3) — a "wrong_attribution"
    # or "not_useful" verdict on a case (the strongest "the AI got this case
    # wrong" signal available) nudges the case toward research
    # (db.nudge_case) instead of only updating source scoring, so the next
    # research tick re-digs via the existing _gap_note machinery.
    feedback_reanalysis_enabled: bool = True
    # Quality prior by media kind (sources/value.py._component_media_prior) —
    # first-hand darknet-forum data is the most valuable signal this system
    # can find, ahead of forensic writeups, feeds, press and blogs.
    # Widened from the original 5-kind set (darknet_forum/forensic/feed/
    # press/blog) to cover the full range of cybercrime-monitor source kinds
    # — see sources/value.py's VALID_MEDIA_KINDS. The old "feed" value is
    # aliased to "threat_feed" (_MEDIA_KIND_ALIASES) rather than migrated, so
    # existing config/DB rows keep resolving without a one-time rewrite.
    media_kind_prior: dict[str, float] = {
        "darknet_forum": 1.0,
        "leak_site": 0.9,
        "marketplace": 0.85,
        "forensic": 0.85,
        "forum": 0.8,
        "paste": 0.75,
        "threat_feed": 0.7,
        "breach_service": 0.7,
        "social": 0.65,
        "press": 0.6,
        "blog": 0.55,
    }

    # ── Semantic search / embeddings ────────────────────────────────────────
    # Separate from the llm_* extraction layer above — embeddings are a
    # distinct call shape (/embeddings, not /chat/completions) and the local
    # default deliberately doesn't depend on an LLM server being up at all.
    # "local": fastembed (ONNX, no torch) running embed_local_model in-process
    # — works with zero external config, all on-machine, multilingual.
    # "openai": any OpenAI-compatible /embeddings endpoint — reuses
    # llm_base_url/llm_api_key unless embed_base_url/embed_api_key are set,
    # so a single already-configured provider (e.g. a real OpenAI account)
    # covers both extraction and embeddings.
    # "none": semantic search disabled — the UI's keyword mode (unaffected,
    # plain SQL LIKE) is the only search available, and the semantic toggle
    # reports itself unavailable rather than silently degrading to keyword.
    #
    # INTEGRITY: every vector is tagged with a fingerprint of
    # (embed_backend, model, dimension). Changing any of those three values
    # invalidates the entire vector index on next startup — vec_cases/
    # vec_items are dropped and rebuilt from scratch by the embedding job,
    # rather than silently mixing vectors from two different embedding
    # spaces (which would make every similarity score meaningless). See
    # embeddings/index.py's init_vectors.
    embed_backend: str = "local"  # "local" | "openai" | "none"
    # bge-m3: multilingual (100+ languages), 1024-dim, strong general-purpose
    # retrieval quality for its size. Downloaded once via fastembed (ONNX,
    # ~2GB) and cached under embed_local_cache_dir on first local use — that
    # first run needs internet even though every run after is offline.
    embed_local_model: str = "BAAI/bge-m3"
    # fastembed defaults its cache to the OS temp dir (tempfile.gettempdir())
    # when this isn't set, which on a systemd-managed deployment with /tmp
    # mounted as tmpfs means the ~2GB model cache silently lives in RAM
    # (permanently occupying it, competing with everything else the process
    # needs) AND gets wiped — forcing a full re-download — on every reboot
    # (see ops notes from 2026-06-21: this caused a sustained OOM crash loop
    # combined with the active embedding session's own memory use). Pointing
    # this at a path under data/ keeps it on persistent disk, alongside
    # db_path, and survives restarts.
    embed_local_cache_dir: Path = Path("data/embed_cache")
    embed_base_url: str = ""  # blank = reuse llm_base_url
    embed_api_key: str = ""  # blank = reuse llm_api_key
    embed_model: str = "text-embedding-3-small"  # used only when embed_backend="openai"
    embed_batch_size: int = 32
    embed_interval_seconds: int = 60
    # Embedding-assisted correlation blocking (quick win C1) — widens
    # pipeline/correlate.py's fuzzy-merge candidate set with the top-k
    # nearest vec_cases neighbors of the item being correlated, in addition
    # to the existing exact/fuzzy-victim blocking. The same conservative
    # adjudicate_merge LLM gate (>= _MERGE_MIN_CONFIDENCE) still decides
    # every merge — this only affects which cases get a chance to be
    # adjudicated. No-ops automatically when embed_backend == "none".
    correlate_embedding_candidates_enabled: bool = True
    correlate_embedding_topk: int = 5

    # CISA KEV (Known Exploited Vulnerabilities) catalog — refreshed daily
    # into the kev_catalog table; see enrich/kev.py.
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    kev_refresh_interval_seconds: int = 86400

    # CVE metadata (CVSS/CWE) enrichment — see enrich/cve_meta.py. Token-free,
    # deterministic HTTP enrichment (issue #18), cached per-CVE in the
    # cve_meta table. Defaults to NVD's public API (no account required); set
    # cve_meta_base_url to a self-hosted or OpenCVE-compatible instance (same
    # query-by-cveId contract) to use that instead. cve_meta_api_key is
    # optional — NVD allows unauthenticated use at a lower rate limit (5
    # req/30s vs 50 req/30s with a free API key).
    cve_meta_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cve_meta_api_key: str = ""
    # How long a cached cve_meta row is trusted before being re-fetched. CVSS/
    # CWE rarely change once published, so a week-long cache is plenty fresh
    # without re-hitting the API for every correlation tick that sees the
    # same recurring CVE (e.g. a widely-exploited one mentioned in many items).
    cve_meta_cache_ttl_hours: int = 168
    # Bounds how many missing-or-stale CVEs a single correlation call will
    # fetch/refresh metadata for (see enrich/cve_meta.get_or_fetch) — keeps
    # pipeline/correlate.py's per-item latency bounded even when an item
    # mentions many CVEs at once. A CVE that's already cached but didn't win
    # a fetch slot is still returned with its last-known (possibly stale)
    # values (stale-while-revalidate); only a CVE that's never been cached
    # AND beyond the cap is absent this round, picking up its metadata next
    # time it's seen (e.g. the next corroborating item).
    cve_meta_fetch_limit_per_call: int = 5
    # FIRST.org EPSS (Exploit Prediction Scoring System) — free, no auth,
    # supports batched lookups (unlike NVD's per-CVE contract) so it's fetched
    # alongside cve_meta in the same pass. Set epss_enabled=False to skip it
    # entirely (e.g. fully offline deployments).
    epss_enabled: bool = True
    epss_base_url: str = "https://api.first.org/data/v1/epss"

    # Items older than this are pruned (see db.py:prune_old_items, wired as a
    # daily job in scheduler.py) to keep the DB from growing unbounded.
    # Effective-critical cases/items are NEVER pruned regardless of age.
    retention_days: int = 90

    # ai_activity rows are retained independently of items because the audit
    # trail is often wanted longer than the raw feed. Defaults to the item
    # retention so existing deployments behave the same until configured.
    activity_retention_days: int = 90

    # ── Public-dashboard DoS resistance ─────────────────────────────────────
    # The dashboard is meant for one analyst's own browser tabs but is
    # commonly reachable publicly (see admin_token's docstring above) —
    # these bound the two resources that scale with concurrent
    # clients/requests instead of being fixed-cost.
    sse_max_subscribers: int = 50
    # Per-IP token bucket on /api/* (see api/app.py's rate_limit_middleware).
    # 0 disables rate limiting entirely.
    rate_limit_per_minute: int = 120

    # ── Self-service accounts (bookmarks only, for now) ─────────────────────
    # Anyone can mint an access key (POST /api/accounts) and paste it into the
    # same X-Admin-Token field the admin token uses. The admin token itself
    # always qualifies as an access key too (see routes.py:resolve_identity).
    # The only capability today is bookmarking cases; notifications are
    # explicitly deferred. There is no hard cap on the number of accounts —
    # growth is bounded by the proof-of-work + rate limit on creation below,
    # and by pruning accounts that go unused for account_expiry_days.
    account_expiry_days: int = 90
    # Proof-of-work difficulty for POST /api/accounts: the client must find a
    # solution whose sha256("{nonce}:{solution}") has this many leading zero
    # bits (see routes.py's _pow_verify). Raises the cost of mass account
    # creation without requiring any state server-side beyond the per-IP rate
    # limit below. ~20 bits is a ~1-3s solve on a laptop in JS.
    account_pow_bits: int = 20
    # Dedicated per-IP limiter for POST /api/accounts and the challenge
    # endpoint — much stricter than the general rate_limit_per_minute above,
    # since account creation is the one publicly-reachable write that can
    # grow the DB without bound if left at the general API rate.
    account_create_rate_per_minute: int = 5
    # How long a PoW challenge (routes.py: GET /api/accounts/challenge)
    # remains solvable before its signature is rejected as expired.
    account_challenge_ttl_seconds: int = 120


settings = Settings()
