"""Single source of truth for the significance enum (info/warn/critical),
its rank ordering, and the score math derived from that rank. Used by
llm/backend.py (extraction verdicts), db.py (case aggregation/eligibility),
pipeline/correlate.py (case creation), and research/agent.py (researcher
reclassification) — see the classification-rework plan for why this used to
be duplicated six ways with no shared definition.

Levels mean slightly different things depending on whether they're attached
to a single feed item (an LLM extraction verdict) or a case (a deduplicated,
possibly-researched incident):

- INFO: stale, insignificant, or unconfirmed — no clear victim (item), or
  the case turned out not to matter on closer inspection.
- WARN: a clear, named victim and a clear act of crime (breach/sale/
  ransomware/exploited CVE), but not currently ongoing — a past/closed
  incident rather than one still unfolding.
- CRITICAL: a clear victim AND the crime is ongoing — new information is
  still being produced (active sale, live extortion, active exploitation).

Note: this is distinct from `false_positive`, a separate, lower tier
(llm/backend.py's _SYSTEM_PROMPT) for items that aren't a specific,
identifiable incident at all. The full ladder, low to high, is:
(deleted) < false_positive < info < warn < critical.
"""

SIGNIFICANCE_LEVELS: tuple[str, ...] = ("info", "warn", "critical")
VALID_SIGNIFICANCE: frozenset[str] = frozenset(SIGNIFICANCE_LEVELS)

SIG_RANK: dict[str, int] = {"info": 1, "warn": 2, "critical": 3}
RANK_SIG: dict[int, str] = {1: "info", 2: "warn", 3: "critical"}

# Raw-SQL CASE expressions that mirror this ranking and cannot import it
# directly (db.py's item_priority view, get_cases_needing_research's ORDER
# BY, and _build_cases_where's min_significance filter) must be kept in sync
# with SIG_RANK by hand — known sync trap, see those call sites.


def significance_score(sig: str) -> float:
    """Normalized 0..1 score for a significance level, derived from its
    rank — e.g. for case.significance_score. Unknown values default to the
    info rank (1) rather than raising, matching the rest of this module's
    lenient .get(..., 1) convention."""
    return SIG_RANK.get(sig, 1) / 3.0


def max_significance(a: str, b: str) -> str:
    """The higher of two significance levels, by rank. Used by the
    item-merge/case-merge "corroboration only ever raises significance"
    rule (db.py's merge_item_into_case/merge_cases) — see those functions'
    docstrings for the caveat that this no longer applies once a case has
    been researched (research/agent.py then owns the level)."""
    return RANK_SIG[max(SIG_RANK.get(a, 1), SIG_RANK.get(b, 1))]
