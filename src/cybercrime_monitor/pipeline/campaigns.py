"""Machine-derived campaign clustering (roadmap #3).

Connected-components over the case_links graph (pipeline/cross_correlate.py's
algorithmic Jaccard-overlap edges — no LLM calls).  Each component with ≥ 2
member cases becomes a campaign; singletons are intentionally excluded (a lone
case has no known sibling yet, not "it forms its own campaign of one").

refresh_campaigns() is the entry point, wired as the scheduler's "_campaigns"
job (gated on settings.campaign_refresh_interval_seconds > 0, with
next_run_time offset 80 so it runs after cross-correlation at offset 75 and
link scores are already fresh).

Token-free — every field is derived algorithmically from case metadata and
case_links scores.
"""

import logging
from collections import Counter

from .. import db
from ..settings import settings

log = logging.getLogger(__name__)


# ── Union-find (path compression + union-by-rank) ────────────────────────────

class _UnionFind:
    def __init__(self):
        self._parent: dict[int, int] = {}
        self._rank: dict[int, int] = {}

    def find(self, x: int) -> int:
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])  # path compression
        return self._parent[x]

    def union(self, x: int, y: int) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        # Union by rank
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1


def _build_components(edges: list[dict]) -> tuple[dict[int, list[int]], dict[int, float]]:
    """Given edges [{case_a, case_b, score}, ...], return
    ({root_id: sorted([member_id, ...])}, {root_id: max_score}) for components
    with >= 2 members."""
    uf = _UnionFind()
    for e in edges:
        uf.union(e["case_a"], e["case_b"])

    # Enumerate all nodes (from edges — nodes with no edges can't form a cluster)
    node_ids: set[int] = set()
    for e in edges:
        node_ids.add(e["case_a"])
        node_ids.add(e["case_b"])

    groups: dict[int, list[int]] = {}
    for node_id in node_ids:
        root = uf.find(node_id)
        groups.setdefault(root, []).append(node_id)

    components = {k: sorted(v) for k, v in groups.items() if len(v) >= 2}

    # Precompute per-component max edge scores in one pass over edges (O(|E|))
    component_max_score: dict[int, float] = {}
    for e in edges:
        a, b, score = e["case_a"], e["case_b"], e["score"]
        ra, rb = uf.find(a), uf.find(b)
        # Both endpoints share the same root after union-find, but guard anyway
        root = ra if ra in components else rb
        if root in components:
            component_max_score[root] = max(component_max_score.get(root, 0.0), score)

    return components, component_max_score


# ── Token-free title / summary derivation ────────────────────────────────────

def _token_free_title(
    dominant_actor: str | None,
    top_crime_type: str | None,
    top_sector: str | None,
    top_country: str | None,
    n: int,
) -> str:
    """Build a deterministic, human-readable campaign title from aggregate fields."""
    if dominant_actor:
        title = f"{dominant_actor} campaign"
    elif top_crime_type:
        title = f"{top_crime_type.replace('_', ' ')} cluster"
    else:
        title = f"Linked incident cluster ({n} cases)"

    if top_sector:
        title += f" targeting {top_sector}"
    elif top_country:
        title += f" in {top_country}"

    return title


def _token_free_summary(
    dominant_actor: str | None,
    top_crime_type: str | None,
    top_sector: str | None,
    top_country: str | None,
    n: int,
    first_seen: str | None,
    last_seen: str | None,
) -> str:
    """One deterministic sentence describing the cluster — no LLM required."""
    parts: list[str] = []
    if dominant_actor:
        parts.append(f"attributed to {dominant_actor}")
    if top_crime_type:
        parts.append(f"involving {top_crime_type.replace('_', ' ')}")
    if top_sector:
        parts.append(f"targeting the {top_sector} sector")
    if top_country:
        parts.append(f"in {top_country}")

    date_range = ""
    if first_seen and last_seen:
        date_range = f" ({first_seen[:10]}–{last_seen[:10]})"

    desc = ", ".join(parts) if parts else "undetermined pattern"
    return f"Machine-derived cluster of {n} linked cases {desc}{date_range}."


# ── Entry point ───────────────────────────────────────────────────────────────

async def refresh_campaigns(conn) -> int:
    """Recompute the campaigns materialized table from case_links.

    1. Fetch all case_links edges ≥ settings.campaign_min_link_score (unbounded
       read — do NOT use db.get_case_links which is per-node and LIMIT 20).
    2. Union-find connected components; keep only those with ≥ 2 members.
    3. Fetch member case data; aggregate fields algorithmically (mirrors
       pipeline/actor_profiles.py's set-union approach — no LLM).
    4. DELETE-then-insert campaigns + rebuild case_campaign index.

    Returns the number of campaigns written.
    """
    from .. import significance as sig_mod  # import here to avoid circular at module-load

    edges = await db.get_all_case_links(conn, min_score=settings.campaign_min_link_score)
    if not edges:
        log.info("[campaigns] no case_links above %.2f — clearing", settings.campaign_min_link_score)
        await db.clear_campaigns(conn)
        return 0

    components, component_max_score = _build_components(edges)
    if not components:
        log.info("[campaigns] no components >= 2 above score %.2f", settings.campaign_min_link_score)
        await db.clear_campaigns(conn)
        return 0

    # Bulk-fetch all member cases in one query
    all_member_ids = sorted({cid for members in components.values() for cid in members})
    all_cases: dict[int, dict] = {c["id"]: c for c in await db.get_cases_by_ids(conn, all_member_ids)}

    await db.clear_campaigns(conn)

    written = 0
    for root, member_ids in sorted(components.items()):
        member_cases = [all_cases[mid] for mid in member_ids if mid in all_cases]
        if len(member_cases) < 2:
            continue

        # ── Aggregate algorithmically (set-union / majority-vote / min-max) ──
        crime_types: set[str] = set()
        sectors: set[str] = set()
        countries: set[str] = set()
        cve_ids: set[str] = set()
        iocs: set[str] = set()
        actor_votes: list[str] = []
        in_kev = False
        max_sig_rank = 0
        max_significance = "info"
        first_seen: str | None = None
        last_seen: str | None = None

        for c in member_cases:
            if c.get("crime_type"):
                crime_types.add(c["crime_type"])
            if c.get("damaged_party_sector"):
                sectors.add(c["damaged_party_sector"])
            if c.get("damaged_party_country"):
                countries.add(c["damaged_party_country"])
            cve_ids.update(c.get("cve_ids") or [])
            iocs.update(c.get("iocs") or [])
            if c.get("attribution"):
                actor_votes.append(c["attribution"].strip())
            if c.get("in_kev"):
                in_kev = True
            rank = sig_mod.SIG_RANK.get(c.get("significance", "info"), 1)
            if rank > max_sig_rank:
                max_sig_rank = rank
                max_significance = c.get("significance", "info")
            fs = c.get("first_seen")
            ls = c.get("last_seen")
            if fs and (first_seen is None or fs < first_seen):
                first_seen = fs
            if ls and (last_seen is None or ls > last_seen):
                last_seen = ls

        # Dominant actor: majority vote by casefold, then lex-smallest casing
        dominant_actor: str | None = None
        if actor_votes:
            vote_counter = Counter(a.casefold() for a in actor_votes)
            top_key = vote_counter.most_common(1)[0][0]
            dominant_actor = min(
                (a for a in actor_votes if a.casefold() == top_key),
                key=str.casefold,
            )

        # campaign_key: lex-smallest member case_key (deterministic anchor)
        case_keys = [c.get("case_key") or str(c["id"]) for c in member_cases]
        campaign_key = min(case_keys)

        # Max link score was precomputed during the edge scan above
        max_score = component_max_score.get(root, 0.0)

        crime_list = sorted(crime_types)
        sector_list = sorted(sectors)
        country_list = sorted(countries)
        top_crime = crime_list[0] if crime_list else None
        top_sector = sector_list[0] if sector_list else None
        top_country = country_list[0] if country_list else None

        title = _token_free_title(dominant_actor, top_crime, top_sector, top_country, len(member_cases))
        summary = _token_free_summary(
            dominant_actor, top_crime, top_sector, top_country,
            len(member_cases), first_seen, last_seen,
        )

        await db.save_campaign(
            conn,
            campaign_key=campaign_key,
            title=title,
            summary=summary,
            case_ids=[c["id"] for c in member_cases],
            dominant_actor=dominant_actor,
            crime_types=crime_list,
            sectors=sector_list,
            countries=country_list,
            cve_ids=sorted(cve_ids),
            iocs=sorted(iocs),
            in_kev=in_kev,
            significance=max_significance,
            first_seen=first_seen,
            last_seen=last_seen,
            max_link_score=max_score,
        )
        written += 1

    await conn.commit()
    log.info("[campaigns] wrote %d campaign(s) from %d edges", written, len(edges))
    return written
