"""Cross-case actor knowledge base (agentic-coordination foundation F3).

Actors, CVEs, and MITRE techniques are aggregated *per case* everywhere else
in the system — research and extraction each start cold on every pass, and
db.get_actor_profile used to recompute its cross-case picture from `cases`
on every single GET /api/actors/{actor} request.

refresh_actor_profiles() is the entry point, run on its own light interval
(scheduler.py's "_actor_profiles" job, mirroring sources/value.py's
_value_refresh pattern) and cached into the actor_profiles table. It is a
single deterministic SQL-scan + Python aggregation pass — no LLM calls,
same spirit as sources/value.py.
"""

import logging

from .. import db

log = logging.getLogger(__name__)


async def refresh_actor_profiles(conn) -> int:
    """Recompute the actor_profiles materialized table from `cases`. Groups
    case-insensitively by attribution (matching the leaderboard's casefold
    merge — "LockBit5" and "lockbit5" are the same actor), unioning CVEs,
    MITRE techniques, sectors, countries, IoCs and victims across every case
    attributed to that actor. Returns the number of actor profiles written."""
    rows = await db.get_attributed_cases_for_actor_profiles(conn)

    groups: dict[str, dict] = {}
    for row in rows:
        key = row["attribution"].strip().lower()
        if not key:
            continue
        g = groups.setdefault(
            key,
            {
                "display_name": row["attribution"].strip(),
                "cve_ids": set(),
                "mitre_techniques": set(),
                "sectors": set(),
                "countries": set(),
                "iocs": set(),
                "victims": set(),
                "case_ids": [],
                "first_seen": None,
                "last_seen": None,
            },
        )
        g["cve_ids"].update(row["cve_ids"])
        g["mitre_techniques"].update(row["mitre_techniques"])
        g["iocs"].update(row["iocs"])
        if row["damaged_party_sector"]:
            g["sectors"].add(row["damaged_party_sector"])
        if row["damaged_party_country"]:
            g["countries"].add(row["damaged_party_country"])
        if row["damaged_party"]:
            g["victims"].add(row["damaged_party"])
        g["case_ids"].append(row["id"])
        if g["first_seen"] is None or (row["first_seen"] or "") < g["first_seen"]:
            g["first_seen"] = row["first_seen"]
        if g["last_seen"] is None or (row["last_seen"] or "") > g["last_seen"]:
            g["last_seen"] = row["last_seen"]

    for actor, g in groups.items():
        await db.upsert_actor_profile(
            conn,
            actor=actor,
            display_name=g["display_name"],
            cve_ids=sorted(g["cve_ids"]),
            mitre_techniques=sorted(g["mitre_techniques"]),
            sectors=sorted(g["sectors"]),
            countries=sorted(g["countries"]),
            iocs=sorted(g["iocs"]),
            victims=sorted(g["victims"]),
            case_ids=g["case_ids"],
            case_count=len(g["case_ids"]),
            victim_count=len(g["victims"]),
            first_seen=g["first_seen"],
            last_seen=g["last_seen"],
        )
    if groups:
        await conn.commit()
    return len(groups)
