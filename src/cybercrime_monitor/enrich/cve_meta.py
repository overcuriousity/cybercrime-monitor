"""CVE metadata enrichment (CVSS severity + CWE weakness type) plus FIRST.org
EPSS exploit-probability scores — issue #18's "more stats on cases" without
spending any LLM tokens: this is deterministic HTTP lookup against public
vulnerability databases, cached per-CVE in the cve_meta table so a
frequently-mentioned CVE (e.g. a widely-exploited one) isn't re-fetched on
every correlation tick that sees it again.

Default source is NVD's public CVE 2.0 API (no account required); point
settings.cve_meta_base_url at a self-hosted or OpenCVE-compatible instance
to use that instead — both expose the same "?cveId=CVE-..." query contract.
EPSS has no equivalent self-host option in practice, so it always targets
FIRST.org's public API (set settings.epss_enabled=False to skip it).

Unlike enrich/kev.py's single daily bulk download, there's no practical
bulk feed for CVSS/CWE/EPSS at this table's scale — get_or_fetch() is a
lazy, per-CVE, TTL-cached lookup instead, called from
pipeline/correlate.py's _resolve_cve_meta.
"""
import logging
from datetime import datetime, timedelta, timezone

from .. import db
from ..http import clearnet_client
from ..settings import settings

log = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_stale(fetched_at: str | None, *, now: datetime) -> bool:
    try:
        fetched = datetime.fromisoformat(fetched_at)
    except (TypeError, ValueError):
        return True
    return now - fetched > timedelta(hours=settings.cve_meta_cache_ttl_hours)


def _parse_nvd_cve(raw: dict) -> dict:
    """Extract (cvss_score, cvss_severity, cwe_ids) from one NVD-shaped `cve`
    object. Tries CVSS v3.1, then v3.0, then v2 — first metric source
    present wins (NVD doesn't always publish all three)."""
    metrics = raw.get("metrics") or {}
    cvss_score = None
    cvss_severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        cvss_data = entries[0].get("cvssData") or {}
        cvss_score = cvss_data.get("baseScore")
        cvss_severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
        break

    cwe_ids: list[str] = []
    for weakness in raw.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value")
            if value and value.startswith("CWE-") and value not in cwe_ids:
                cwe_ids.append(value)

    return {"cvss_score": cvss_score, "cvss_severity": cvss_severity, "cwe_ids": cwe_ids}


async def _fetch_one_nvd(client, cve_id: str) -> dict | None:
    headers = {"apiKey": settings.cve_meta_api_key} if settings.cve_meta_api_key else {}
    try:
        resp = await client.get(settings.cve_meta_base_url, params={"cveId": cve_id}, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.info("[cve_meta] NVD lookup failed for %s: %s", cve_id, exc)
        return None

    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not vulns:
        return None
    cve_obj = vulns[0].get("cve") or {}
    return _parse_nvd_cve(cve_obj)


async def _fetch_epss(client, cve_ids: list[str]) -> dict[str, float]:
    """EPSS supports a single batched lookup (comma-separated cve= values),
    unlike NVD's per-CVE contract — fetched once per get_or_fetch call
    rather than once per CVE."""
    if not cve_ids:
        return {}
    try:
        resp = await client.get(settings.epss_base_url, params={"cve": ",".join(cve_ids)})
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.info("[cve_meta] EPSS lookup failed for %s: %s", cve_ids, exc)
        return {}

    out = {}
    for row in (data.get("data") or []) if isinstance(data, dict) else []:
        cve_id = str(row.get("cve", "")).strip().upper()
        try:
            score = float(row.get("epss"))
        except (TypeError, ValueError):
            continue
        if cve_id:
            out[cve_id] = score
    return out


async def get_or_fetch(db_conn, cve_ids: list[str]) -> dict[str, dict]:
    """Cached metadata for the given CVE ids. Of the CVEs that are missing
    or stale, up to settings.cve_meta_fetch_limit_per_call are fetched and
    (re)cached this call — see that setting's docstring for why this is
    bounded. Returns a dict keyed by cve_id.

    Stale-while-revalidate, not strict TTL: a CVE that's cached but past its
    TTL and didn't win a fetch slot this call is still returned with its
    last-known (stale) values, rather than being dropped — for a slowly-
    changing field like CVSS this is far preferable to a case's cvss_max
    flickering to a lower/None value purely because of cache aging under
    fetch-cap pressure. It will be refreshed on a later call once it gets a
    slot. A CVE that has *never* been fetched and is also beyond this call's
    cap is simply absent from the result and picks up its metadata next time
    it's seen (e.g. the next corroborating item) — there's no stale value to
    fall back to yet."""
    if not cve_ids:
        return {}

    cached = await db.get_cve_meta(db_conn, cve_ids)
    now = datetime.now(timezone.utc)
    to_fetch = [
        c for c in cve_ids
        if c not in cached or _is_stale(cached[c]["fetched_at"], now=now)
    ][: settings.cve_meta_fetch_limit_per_call]

    if not to_fetch:
        return cached

    async with clearnet_client(timeout=20.0) as client:
        epss_scores = await _fetch_epss(client, to_fetch) if settings.epss_enabled else {}
        entries = []
        for cve_id in to_fetch:
            nvd = await _fetch_one_nvd(client, cve_id)
            entry = {
                "cve_id": cve_id,
                "cvss_score": nvd["cvss_score"] if nvd else None,
                "cvss_severity": nvd["cvss_severity"] if nvd else None,
                "cwe_ids": nvd["cwe_ids"] if nvd else [],
                "epss": epss_scores.get(cve_id),
                "fetched_at": _now_iso(),
            }
            entries.append(entry)
            cached[cve_id] = entry

    await db.upsert_cve_meta(db_conn, entries)
    return cached
