"""CISA Known Exploited Vulnerabilities (KEV) catalog — downloaded daily
into the kev_catalog table (see db.py:replace_kev_catalog) and looked up per
CVE to flag cases.in_kev. A vulnerability appearing in this catalog means
CISA has confirmed it is being actively exploited in the wild — distinct
from (and a stronger signal than) merely "a CVE was mentioned."
"""
import logging

from .. import db
from ..http import clearnet_client
from ..settings import settings

log = logging.getLogger(__name__)


def _parse_kev_entry(raw: dict) -> dict | None:
    cve_id = str(raw.get("cveID", "")).strip().upper()
    if not cve_id:
        return None
    return {
        "cve_id": cve_id,
        "vendor": raw.get("vendorProject"),
        "product": raw.get("product"),
        "vuln_name": raw.get("vulnerabilityName"),
        "date_added": raw.get("dateAdded"),
        "due_date": raw.get("dueDate"),
        "known_ransomware": raw.get("knownRansomwareCampaignUse"),
        "notes": raw.get("notes"),
    }


async def refresh_kev_catalog(db_conn) -> int:
    """Download CISA's KEV feed and replace the local cache. Returns the
    number of entries stored, or -1 on failure (logged; the existing cache
    is left untouched — see replace_kev_catalog's docstring)."""
    try:
        async with clearnet_client(timeout=60.0) as client:
            resp = await client.get(settings.kev_feed_url)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        log.error("[kev] failed to download catalog: %s", exc)
        return -1

    raw_entries = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    entries = [e for e in (_parse_kev_entry(r) for r in raw_entries) if e is not None]

    count = await db.replace_kev_catalog(db_conn, entries)
    log.info("[kev] refreshed catalog: %d entries", count)
    return count


async def lookup_cves(db_conn, cve_ids: list[str]) -> dict[str, dict]:
    """Look up which of the given CVE ids are in the KEV catalog. Returns a
    dict keyed by cve_id for just the ones that matched — callers check
    `if cve_id in result` rather than handling None entries."""
    if not cve_ids:
        return {}
    rows = await db.lookup_kev(db_conn, cve_ids)
    return {r["cve_id"]: r for r in rows}
