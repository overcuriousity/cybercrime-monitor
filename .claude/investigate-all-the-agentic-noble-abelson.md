# Agentic Subsystem Integration — Proposals Catalog

## Context

`cybercrime-monitor` runs **12 subsystems** (8 AI-driven) as independent
APScheduler jobs in one process. They are *runtime-decoupled by design*: each
drains its own SQL-backed queue on a fixed timer and writes results to shared
SQLite tables. A slow Hermes run never stalls ingest — this robustness is a
deliberate, valuable property and every proposal below preserves it.

The cost of that design: **the subsystems almost never share intelligence or
signal each other.** Collectors poll on static intervals regardless of what
they've yielded. Research works one case in isolation; its findings (and the
write-up domains it visited) don't reach discovery. Cross-correlation links
cases but the link is a dead end — it never raises priority. Human feedback
flows only into source scoring, never back into re-analysis. Embeddings power
search but not correlation.

There is already one proven coordination primitive in the codebase:
`cases.research_requested_at` — a nudge column the API/research-loop *writes*
and `db.get_cases_needing_research` *reads* to jump the queue
(`research/agent.py:96`, the `_gap_note` mechanism). **Most proposals below
generalize that exact pattern**: a subsystem writes a lightweight signal
(a column, a queue row, an existing audit table) that another subsystem already
polling SQL picks up on its next tick. No message broker, no new process, no
shared-connection changes — fully within the current architecture.

**Goal weighting:** all four areas (collection, acquisition/research, analysis,
presentation) are in scope. **Constraint:** stay within single-process /
single-SQLite-connection, token-frugal (prefer deterministic over LLM),
centralized `prompts.py`, transport-agnostic LLM layer, and the public
`ai_activity` audit trail.

---

## Unifying theme: a shared "signal bus" over existing tables

Rather than 13 bespoke wires, most ideas compose from **three cheap primitives**,
each already half-present:

1. **Nudge columns** — like `research_requested_at`. A column another loop's
   eligibility SQL already (or trivially can) consult. Generalize to a
   `case_priority_boost` / `requested_by` so any subsystem can escalate a case.
2. **Derived intel tables refreshed on a light timer** — like `source_value`.
   A materialized aggregate (e.g. `actor_profiles`) computed deterministically
   from existing rows, read by prompt-builders and the UI.
3. **Causal links in `ai_activity`** — add an optional `caused_by` ref so the
   flat audit log becomes a traversable provenance graph for free.

Build these once and most proposals become small.

---

## A. Data Collection (dynamic, value-aware scheduling)

### A1. Value-driven adaptive polling intervals ✅ Implemented  ⭐ high-impact, low-effort
**Problem:** `sources/value.py` already scores every source (yield, case
contribution, health, recency, diversity) and `_value_refresh` caches it — but
*only* heal/prune/discover act on it. A source that reliably founds confirmed
critical cases polls on the same static `interval_seconds` as a dead one.
**Mechanism:** After `compute_all()` in the `_value_refresh` job, derive an
*effective interval* per source (e.g. `valuable` → ×0.5, `marginal` → ×2,
clamped to sane bounds) and call the existing
`scheduler.reschedule_source` — the exact live-reschedule path heal already
uses. Purely a function of the cached snapshot; no new LLM calls.
**Files:** `sources/value.py` (emit suggested interval), `scheduler.py`
(`_refresh_values` → reschedule loop, reuse `reschedule_source`).
**Fit:** deterministic, reversible (intervals recompute each refresh), audited
via a new `ai_activity` `subsystem="scheduler"` event.

### A2. Event-driven collection bursts ("hot source" boost) ⬜ Not started
**Problem:** When research confirms a critical case or an analyst submits an
investigation touching source X, X keeps polling at its lazy baseline — exactly
when fresh follow-up posts are most likely.
**Mechanism:** On a confirm/critical promotion (`research/agent.py`
`apply_research_findings`) or investigation match, temporarily shorten the
contributing sources' intervals via `reschedule_source` with a TTL that A1's
next refresh naturally relaxes back.
**Files:** `research/agent.py`, `research/investigate.py`, `scheduler.py`.
**Fit:** builds entirely on A1's primitive; self-healing TTL via the refresh
cycle so no cleanup state to track.

---

## B. Data Acquisition / Research (cross-agent intel sharing)

### B1. Research → Discovery source hand-off ✅ Implemented  ⭐ high-impact, low-effort
**Problem:** The research agent visits and cites technical write-ups
(BleepingComputer, DFIR Report, vendor blogs) — these are *exactly* the
high-value sources discovery hunts for from scratch. Today those URLs land in
`research_runs.sources` as inert evidence and are never mined.
**Mechanism:** Discovery (`research/discover.py`) reads recent
`research_runs.sources` domains not already in `sources.yaml` as **pre-warmed
candidates** — the research agent already vouched for their relevance. Run them
through the existing discover validation (RSS-probe / forum-scrape
`_MIN_VALID_ROWS`) before adding. Skips a whole speculative search leg.
**Files:** `research/discover.py` (new candidate source = research-run domains),
reuse existing `db` accessor for `research_runs`.
**Fit:** reuses discovery's validation + `sources/writer.py`; no new prompts.

### B2. Cross-signal research prioritization 🚧 In progress (foundation only — see priority_boost in Recommended sequencing)  ⭐ high-impact, medium-effort
**Problem:** `db.get_cases_needing_research` orders by significance + cooldown
only. It ignores three strong "this is hot" signals the system already
computes: (a) the case is `case_links`-clustered with a confirmed-critical
peer, (b) its CVE just entered the KEV catalog, (c) an analyst just gave it
positive feedback or is actively viewing it.
**Mechanism:** Generalize `research_requested_at` into a small priority signal
(`requested_by`, `priority_boost`). Have cross-correlation (B/C overlap),
the KEV refresh, and feedback writes *set* the boost; research's eligibility
SQL reads it. Each writer already runs on its own tick — they just stamp a
column.
**Files:** `pipeline/cross_correlate.py`, `enrich/kev.py`, `api/routes.py`
(feedback), `db.py` (eligibility SQL + nudge helper), `research/agent.py`.
**Fit:** the canonical generalization of the existing nudge primitive.

### B3. Shared actor / threat-entity knowledge base ✅ Implemented (foundation F3 — KB + dossier UI consumption (D2) not yet built)  ⭐ high-impact, medium-effort
**Problem:** Actors, CVEs, TTPs are aggregated *per case*. The system never
forms a cross-case picture of "actor X uses CVE-Y against sector Z," so each
research pass and each extraction starts cold. `/api/actors/{actor}` recomputes
from cases on every request.
**Mechanism:** A deterministic `actor_profiles` materialized table (refreshed
on a light timer like `source_value`): per actor → union of CVEs, MITRE
techniques, victim sectors/countries, IoCs, linked case ids, first/last seen.
Then: (1) research prompt-builder injects the actor's known arsenal so a pass
*targets gaps* instead of re-deriving knowns; (2) extraction can be given the
top actors as hint context; (3) presentation gets a real dossier (see D2).
**Files:** new `db` table + refresh job in `scheduler.py`, consumed in
`research/agent.py:_build_prompt` (via `prompts.py` template field),
`api/routes.py`.
**Fit:** deterministic aggregation (no LLM to build the profile); prompt change
stays in `prompts.py`; reuses the `source_value` refresh-job pattern.

### B4. Investigation brief as a steering signal ⬜ Not started
**Problem:** An analyst's free-text investigation brief is the strongest
possible statement of "what matters right now," but it only drives the single
investigation run.
**Mechanism:** When an investigation confirms/creates a case, carry its brief
keywords as a `priority_boost` (B2) onto semantically/algorithmically related
existing cases so research revisits them, and feed its domain findings to B1.
**Files:** `research/investigate.py`, reuse B1/B2 plumbing.
**Fit:** pure reuse of B1+B2 once those exist.

---

## C. Data Analysis (closing the loops)

### C1. Embedding-assisted correlation blocking ✅ Implemented  ⭐ medium-impact, low-effort
**Problem:** `pipeline/correlate.py` generates merge candidates from normalized
victim/actor string blocking + shared CVE/IoC (`db.find_candidate_cases`). It
misses paraphrased or differently-spelled victims ("Acme Corp" vs "Acme
Corporation Inc"). Meanwhile `vec_items`/`vec_cases` embeddings exist but power
*only* search.
**Mechanism:** Add a vector-similarity candidate channel to `_try_fuzzy_merge`:
top-k nearest case vectors as additional candidates fed to the same LLM
`adjudicate_merge` gate (≥0.6 confidence) that already guards merges. The
conservative adjudicator stays the safety net, so recall improves without
raising wrong-merge risk.
**Files:** `pipeline/correlate.py`, `embeddings/index.py` (k-NN query helper).
**Fit:** reuses existing embeddings + existing adjudication gate; no new prompt.

### C2. Cross-correlation → significance / research feedback loop ✅ Implemented  ⭐ high-impact, low-effort
**Problem:** `pipeline/cross_correlate.py` is a dead end signal-wise: it writes
`case_links` and stops. If a quiet `info` case gets linked into a cluster where
a peer is confirmed-critical or KEV-exploited, nothing escalates it.
**Mechanism:** When a new high-score link attaches a case to a more-severe
cluster, set B2's `priority_boost` (route it to research) and/or nudge
significance up one rung — gated, audited, and reversible by the existing
mechanical `significance_decay` if research doesn't corroborate.
**Files:** `pipeline/cross_correlate.py`, `db.py` (nudge helper), reuse B2.
**Fit:** algorithmic trigger, LLM only via the downstream research pass.

### C3. Feedback-triggered re-analysis ✅ Implemented  ⭐ medium-impact, low-effort
**Problem:** Human feedback (`wrong_attribution`, `noise`) flows *only* into
`sources/value.py` scoring. A "wrong_attribution" verdict — the strongest
possible "the AI got this case wrong" signal — never causes the case itself to
be re-examined.
**Mechanism:** On a `wrong_attribution`/`not_useful` verdict for a case, set
`research_requested_at` with a targeted gap-note (reuse `_gap_note`
machinery) so the next research tick re-digs attribution; optionally flag the
merge for analyst review. Human verdict → agent action, not just a score.
**Files:** `api/routes.py` (feedback handler), `research/agent.py` (gap-note
already supports this), `db.py`.
**Fit:** direct reuse of the existing nudge + gap-note primitives.

### C4. Evaluator ↔ research escalation ⬜ Not started
**Problem:** The synthetic-feedback evaluator (`research/evaluator.py`) and the
research agent never talk. The evaluator may judge a case's items highly useful
while the case sits under-researched, or flag wrong attribution that no one
acts on.
**Mechanism:** Route the evaluator's verdicts through the same C3 path — a
strong synthetic signal sets a (discounted) `priority_boost`, consistent with
how `feedback_agent_weight` already discounts agent vs human feedback.
**Files:** `research/evaluator.py`, reuse B2/C3.
**Fit:** reuses C3; respects existing agent-weight discounting philosophy.

---

## D. Presentation (surfacing the coordination)

### D1. Cross-agent provenance graph (Activity tab) 🚧 In progress (foundation F2 — ai_activity.caused_by + write path exist and are exercised by C2; timeline UI/endpoint not yet built)  ⭐ medium-impact, low-effort
**Problem:** `ai_activity` is a flat chronological log. The story "item ingested
→ classified → case created → researched (run #N, confirmed) → spawned
discovery of domain X → became source Y" is *in the data* (`research_runs`,
`case_links`, `source_heal_proposals`, `ai_activity`) but never assembled.
**Mechanism:** Add an optional `caused_by` ref to `ai_activity` (subsystems
stamp it when one action triggers another — natural once B/C nudges exist), and
a `GET /api/cases/{id}/timeline` that joins the per-case agent history into one
ordered narrative. Render as a timeline on the case detail view.
**Fit:** mostly a join over existing tables + one nullable column; turns the
new coordination into a visible, auditable feature (preserves transparency
value).

### D2. Actor dossiers & threat-landscape narratives ⬜ Not started (B3's actor_profiles KB is available to build on)
**Problem:** The Landscape tab shows aggregate charts; there's no per-actor deep
view despite the data existing.
**Mechanism:** Surface B3's `actor_profiles`: per-actor page with CVE arsenal,
MITRE TTP matrix, targeted sectors/geographies, victim timeline, and linked
cases. Extend the existing `/api/actors/{actor}` endpoint to read the
materialized profile.
**Files:** `api/routes.py`, `api/static/app.js`, `index.html`.
**Fit:** consumes B3; pure read-side aggregation.

### D3. Coverage / "thin case" surfacing ⬜ Not started
**Problem:** Analysts can't see where the agents *haven't* reached — cases with
no research run, single-source corroboration, or low confidence look the same
as well-vetted ones.
**Mechanism:** A deterministic coverage score per case (has-research?,
#sources, mean confidence, age-since-research) surfaced as a badge/filter, so
analysts can steer manual investigation (and B2 can auto-prioritize the
thinnest high-significance cases).
**Files:** `db.py` (coverage query), `api/routes.py`, `api/static/app.js`.
**Fit:** deterministic; doubles as a prioritization input for B2.

---

## Recommended sequencing

Build the **three primitives first**, then proposals snap on cheaply:

1. **Foundation ✅ Implemented:** generalize the nudge column
   (`priority_boost`/`requested_by`, see `db.nudge_case`)
   + `ai_activity.caused_by` (see `db.log_ai_activity`) + the
   `actor_profiles` refresh job (`pipeline/actor_profiles.py`,
   scheduler.py's `_actor_profiles` job).
2. **Quick wins (low-effort, high-impact) ✅ Implemented:** A1 (adaptive
   polling), B1 (research→discovery), C2 (cross-correlation escalation), C3
   (feedback re-analysis), C1 (embedding-assisted merge).
3. **Bigger payoffs:** B2 (cross-signal research priority) 🚧 — the
   priority_boost primitive + its C2/C3 writers exist, but the KEV-refresh
   writer doesn't yet; B3 (actor KB) ✅ — `actor_profiles` exists and backs
   `get_actor_profile`; D1 (provenance timeline) 🚧 — `caused_by` exists and
   is stamped by C2, but no `/api/cases/{id}/timeline` or UI yet; D2
   (dossiers) ⬜ not started.
4. **Compose:** A2, B4, C4, D3 — all reuse the above, ⬜ not started.

Each is independently shippable and independently disablable (matching the
existing `*_interval_seconds=0` kill-switch philosophy).

---

## Verification (per the catalog's nature — validating idea value cheaply)

This deliverable is a **proposals catalog**, not an implementation. Validate
direction before building:

- **Confirm the gaps are real, not already wired:** grep for any existing
  reader of `source_value` beyond heal/discover (A1), any consumer of
  `research_runs.sources` (B1), and any path from `feedback` rows into
  `cases`/`research_requested_at` (C3). Expect none — confirming the seams.
- **Dry-run the foundation on a copy of `data/items.db`:** materialize an
  `actor_profiles` aggregate read-only and eyeball whether cross-case actor
  pictures look coherent (B3) before committing schema.
- **Cheap A/B for C1:** run the proposed vector-kNN candidate query against
  recent cases offline and count how many *true* merges string-blocking missed
  — quantifies recall lift before touching the live correlator.
- **For anything built:** assert the new coordination emits `ai_activity` rows
  (transparency invariant) and that each new loop honors a
  `*_interval_seconds`/enable kill-switch, then watch the Activity tab + SSE
  stream end-to-end on a local run.
