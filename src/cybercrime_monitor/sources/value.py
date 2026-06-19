"""Investigation-value scoring for sources — the single signal the
autonomous source-management loop (research/heal.py) acts on instead of
static thresholds, per the explicit steer: a source's worth is judged
*relative to its peers and its own history*, not against a fixed
confidence/error-count cutoff baked into settings.

compute_all() is the entry point, run on its own light interval
(scheduler.py's "_value_refresh" job) and cached into the source_value
table — both the dashboard and the heal/prune/discover loop read the cached
snapshot rather than recomputing on every request.

Score components (each folded to 0.0-1.0, see _component_* below):
  - yield: extraction usefulness (non-false-positive rate, share reaching
    warn/critical, mean confidence) over the window.
  - case_contribution: how much this source's items end up corroborating
    or founding cases, weighted toward confirmed/significant ones.
  - health: collector reliability (consecutive errors, ever-succeeded).
  - feedback: analyst-supplied verdicts (db.feedback) on items/cases this
    source contributed to.
  - recency: decay if a source has gone quiet relative to its own configured
    interval — a once-good, now-silent source drifts down over time instead
    of keeping a stale high score forever.

Classification is *relative*: a source is "dead" only if it has never once
produced a successful fetch while peers are succeeding (an objective,
non-judgement signal), otherwise its blended score is ranked against the
population's own distribution this run — top third "valuable", bottom
third "marginal" (a candidate for pruning only when corroborated by zero
case contribution / negative feedback — see research/heal.py's
should_prune()), middle third "marginal" by default. There is no fixed
numeric cutoff anywhere in this module.
"""
import logging
from datetime import datetime, timedelta, timezone

from .. import db
from .. import health
from ..scheduler import load_sources

log = logging.getLogger(__name__)

# How far back "recent yield/contribution/feedback" looks — long enough to
# smooth over a source's natural posting cadence, short enough that a source
# which used to be good but has been silent for months doesn't coast on
# ancient history forever.
_WINDOW_DAYS = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _component_yield(stats: dict | None) -> float | None:
    if not stats or not stats.get("total"):
        return None
    total = stats["total"]
    useful_rate = (stats.get("useful") or 0) / total
    significant_rate = (stats.get("significant") or 0) / total
    mean_conf = stats.get("mean_confidence")
    mean_conf = float(mean_conf) if mean_conf is not None else 0.5
    return max(0.0, min(1.0, (useful_rate + significant_rate + mean_conf) / 3.0))


def _component_case_contribution(stats: dict | None, *, max_cases_touched: int) -> float | None:
    if not stats or not stats.get("cases_touched"):
        return None
    cases_touched = stats["cases_touched"]
    # Relative to the best-contributing source this run, not an absolute count
    # — a niche source that reliably founds a handful of real cases scores
    # well even if a high-volume RSS feed touches ten times as many cases.
    breadth = cases_touched / max(1, max_cases_touched)
    confirmed_rate = (stats.get("confirmed_links") or 0) / cases_touched
    significant_rate = (stats.get("significant_links") or 0) / cases_touched
    return max(0.0, min(1.0, (breadth + confirmed_rate + significant_rate) / 3.0))


def _component_health(source_id: str) -> tuple[float | None, bool]:
    """Returns (score, ever_succeeded). ever_succeeded=False + a run attempt
    on record is the objective "structurally broken" signal classify() uses
    to call a source dead outright, independent of the relative scoring."""
    h = health.get(source_id)
    if h is None or h.last_run_at is None:
        return None, True  # never run yet — no opinion, not "dead"
    ever_succeeded = h.last_success_at is not None
    if not ever_succeeded:
        return 0.0, False
    # Decays toward 0 as consecutive_errors climbs; a single transient error
    # barely moves it, a long unbroken failure streak does.
    score = 1.0 / (1.0 + h.consecutive_errors)
    return score, True


def _component_feedback(counts: dict[str, int] | None) -> float | None:
    if not counts:
        return None
    positive = counts.get("useful", 0)
    negative = counts.get("not_useful", 0) + counts.get("noise", 0) + counts.get("wrong_attribution", 0)
    total = positive + negative
    if total == 0:
        return None
    return max(0.0, min(1.0, positive / total))


def _component_recency(source_id: str, interval_seconds: int) -> float:
    h = health.get(source_id)
    if h is None or h.last_success_at is None:
        return 0.5  # unknown — neutral, let other components decide
    try:
        last = datetime.fromisoformat(h.last_success_at)
    except ValueError:
        return 0.5
    elapsed = (_now() - last).total_seconds()
    # A source that's "due" (elapsed <= its own interval) scores 1.0; one
    # that's gone 10x its interval without a success decays toward 0.
    ratio = elapsed / max(60, interval_seconds)
    return max(0.0, min(1.0, 1.0 - (ratio / 10.0)))


_WEIGHTS = {
    "yield": 0.30,
    "case_contribution": 0.30,
    "health": 0.20,
    "feedback": 0.10,
    "recency": 0.10,
}


def _blend(components: dict[str, float | None]) -> float:
    """Weighted average over whichever components have data — a brand-new
    source with no extraction history yet isn't penalized for the
    components it hasn't had a chance to earn, it's just judged on what's
    available (health + recency, which always have a value)."""
    total_weight = 0.0
    acc = 0.0
    for name, value in components.items():
        if value is None:
            continue
        w = _WEIGHTS[name]
        acc += value * w
        total_weight += w
    if total_weight == 0:
        return 0.5
    return acc / total_weight


async def compute_all(conn) -> dict[str, dict]:
    """Score every configured source and persist the snapshot. Returns
    {source_id: {"score", "classification", "components"}}."""
    sources = load_sources()
    if not sources:
        return {}

    since_iso = (_now() - timedelta(days=_WINDOW_DAYS)).isoformat()
    yield_stats = await db.yield_stats_by_source(conn, since_iso=since_iso)
    contribution_stats = await db.case_contribution_by_source(conn, since_iso=since_iso)
    feedback_stats = await db.aggregate_feedback_by_source(conn, since_iso=since_iso)
    max_cases_touched = max((s.get("cases_touched") or 0) for s in contribution_stats.values()) if contribution_stats else 0

    raw: dict[str, dict] = {}
    for src in sources:
        sid = src["id"]
        health_score, ever_succeeded = _component_health(sid)
        components = {
            "yield": _component_yield(yield_stats.get(sid)),
            "case_contribution": _component_case_contribution(
                contribution_stats.get(sid), max_cases_touched=max_cases_touched
            ),
            "health": health_score,
            "feedback": _component_feedback(feedback_stats.get(sid)),
            "recency": _component_recency(sid, src.get("interval_seconds", 600)),
        }
        score = _blend(components)
        raw[sid] = {
            "score": score,
            "ever_succeeded": ever_succeeded,
            "components": {k: v for k, v in components.items() if v is not None},
            "case_contribution_raw": contribution_stats.get(sid),
            "feedback_raw": feedback_stats.get(sid),
        }

    # Relative ranking: only sources with a real run history (last_run_at
    # set) participate in the percentile split — a source that hasn't ticked
    # yet has no opinion formed about it.
    scored_ids = [sid for sid in raw if health.get(sid) and health.get(sid).last_run_at]
    scores = sorted(raw[sid]["score"] for sid in scored_ids)
    lo_cut = scores[len(scores) // 3] if scores else 0.0
    hi_cut = scores[(2 * len(scores)) // 3] if scores else 1.0

    out: dict[str, dict] = {}
    for sid, r in raw.items():
        if not r["ever_succeeded"]:
            classification = "dead"
        elif sid not in scored_ids:
            classification = "marginal"  # no history yet — treat cautiously, not valuable
        elif r["score"] >= hi_cut and r["score"] > lo_cut:
            classification = "valuable"
        elif r["score"] <= lo_cut:
            classification = "marginal"
        else:
            classification = "marginal"
        await db.save_source_value(
            conn, source_id=sid, score=r["score"], classification=classification, components=r["components"]
        )
        out[sid] = {"score": r["score"], "classification": classification, "components": r["components"]}

    log.info(
        "[value] scored %d source(s): %d valuable, %d marginal, %d dead",
        len(out),
        sum(1 for v in out.values() if v["classification"] == "valuable"),
        sum(1 for v in out.values() if v["classification"] == "marginal"),
        sum(1 for v in out.values() if v["classification"] == "dead"),
    )
    return out


def should_apply_heal(*, value: dict | None, probe_ok: bool) -> bool:
    """Purpose-driven apply guardrail for a heal fix: a probe must pass
    (the proposed URL must actually be reachable — never apply on hope
    alone), AND the source must not already be a confirmed write-off — i.e.
    there's no value snapshot yet (give it a chance) or it isn't already
    "marginal" with corroborating negative signal (see should_prune; a
    source heal shouldn't resurrect something the loop just decided to
    prune). No static confidence number is consulted."""
    if not probe_ok:
        return False
    if value is None:
        return True
    if value.get("classification") == "dead":
        return False
    if value.get("classification") == "marginal":
        components = value.get("components", {})
        no_contribution = components.get("case_contribution") in (None, 0.0)
        feedback_score = components.get("feedback")
        negative_feedback = feedback_score is not None and feedback_score < 0.5
        if no_contribution and negative_feedback:
            return False
    return True


def should_prune(*, value: dict | None, min_history: bool) -> bool:
    """Purpose-driven prune guardrail: a source is pruned when it's "dead"
    (never produced a successful fetch), or "marginal" with corroborating
    zero-value evidence (no case contribution at all AND net-negative
    feedback). A "marginal" source with some case contribution, or with no
    feedback opinion either way, is left alone — marginal isn't a verdict on
    its own, only dead-with-evidence is. `min_history` (the source has had a
    real run history for at least the value-scoring window) gates BOTH
    branches — a brand-new source that hasn't had a chance to prove itself
    yet is never pruned just for having no data."""
    if value is None or not min_history:
        return False
    if value["classification"] == "dead":
        return True
    if value["classification"] == "marginal":
        components = value.get("components", {})
        no_contribution = components.get("case_contribution") in (None, 0.0)
        feedback_score = components.get("feedback")
        negative_feedback = feedback_score is not None and feedback_score < 0.5
        return no_contribution and negative_feedback
    return False
