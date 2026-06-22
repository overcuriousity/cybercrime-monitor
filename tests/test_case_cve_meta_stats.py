import json
from datetime import datetime, timezone

import pytest

from cybercrime_monitor import db as db_module
from cybercrime_monitor.models import Item


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _insert_item(conn, **kwargs):
    token = datetime.now(timezone.utc).isoformat()
    item = Item(
        source_id=kwargs.get("source_id", "test-source"),
        source_name=kwargs.get("source_name", "Test Source"),
        title=kwargs.get("title", f"item-{token}"),
        url=kwargs.get("url", f"https://example.com/{token}"),
        snippet=kwargs.get("snippet", "snippet"),
        dedupe_key=kwargs.get("dedupe_key", f"dk-{token}"),
        content_key=kwargs.get("content_key", ""),
    )
    item_id = await db_module.insert_item(conn, item)
    await conn.commit()
    return item_id


@pytest.mark.asyncio
async def test_create_case_stores_cvss_cwe_epss_mitre(db_conn):
    item_id = await _insert_item(db_conn)
    case_id = await db_module.create_case(
        db_conn,
        case_key="case-1",
        title="Title",
        summary="summary",
        crime_type="ransomware",
        attribution=None,
        attribution_confidence=None,
        damaged_party=None,
        damaged_party_sector=None,
        damaged_party_country=None,
        significance="warn",
        significance_score=2.0,
        cve_ids=["CVE-2024-1"],
        in_kev=False,
        item_id=item_id,
        event_at=_iso(),
        iocs=[],
        cvss_max=9.8,
        cwe_ids=["CWE-79"],
        epss_max=0.42,
        mitre_techniques=["T1190"],
    )
    case = await db_module.get_case_by_id(db_conn, case_id)
    assert case["cvss_max"] == 9.8
    assert case["epss_max"] == 0.42
    assert json.loads(case["cwe_ids"]) == ["CWE-79"]
    assert json.loads(case["mitre_techniques"]) == ["T1190"]


@pytest.mark.asyncio
async def test_merge_item_into_case_takes_max_and_unions(db_conn):
    item_id1 = await _insert_item(db_conn)
    case_id = await db_module.create_case(
        db_conn,
        case_key="case-2",
        title="Title",
        summary="summary",
        crime_type="ransomware",
        attribution=None,
        attribution_confidence=None,
        damaged_party=None,
        damaged_party_sector=None,
        damaged_party_country=None,
        significance="warn",
        significance_score=2.0,
        cve_ids=["CVE-2024-1"],
        in_kev=False,
        item_id=item_id1,
        event_at=_iso(),
        iocs=[],
        cvss_max=5.0,
        cwe_ids=["CWE-79"],
        epss_max=0.1,
        mitre_techniques=["T1190"],
    )

    item_id2 = await _insert_item(db_conn)
    await db_module.merge_item_into_case(
        db_conn,
        case_id=case_id,
        item_id=item_id2,
        significance="warn",
        cve_ids=["CVE-2024-2"],
        in_kev=False,
        crime_type=None,
        attribution=None,
        attribution_confidence=None,
        damaged_party_sector=None,
        damaged_party_country=None,
        event_at=_iso(),
        iocs=[],
        cvss_max=9.8,  # higher than the founding item's — max should win
        cwe_ids=["CWE-89"],
        epss_max=0.05,  # lower than the founding item's — max should keep 0.1
        mitre_techniques=["T1059.001"],
    )

    case = await db_module.get_case_by_id(db_conn, case_id)
    assert case["cvss_max"] == 9.8
    assert case["epss_max"] == 0.1
    assert set(json.loads(case["cwe_ids"])) == {"CWE-79", "CWE-89"}
    assert set(json.loads(case["mitre_techniques"])) == {"T1190", "T1059.001"}


@pytest.mark.asyncio
async def test_merge_item_into_case_handles_none_meta_without_clobbering(db_conn):
    """A corroborating item with no CVEs/techniques of its own (cvss_max=None
    etc.) must not erase the case's already-known aggregate values."""
    item_id1 = await _insert_item(db_conn)
    case_id = await db_module.create_case(
        db_conn,
        case_key="case-3",
        title="Title",
        summary="summary",
        crime_type="ransomware",
        attribution=None,
        attribution_confidence=None,
        damaged_party=None,
        damaged_party_sector=None,
        damaged_party_country=None,
        significance="warn",
        significance_score=2.0,
        cve_ids=["CVE-2024-1"],
        in_kev=False,
        item_id=item_id1,
        event_at=_iso(),
        iocs=[],
        cvss_max=7.5,
        cwe_ids=["CWE-79"],
        epss_max=0.2,
        mitre_techniques=["T1190"],
    )

    item_id2 = await _insert_item(db_conn)
    await db_module.merge_item_into_case(
        db_conn,
        case_id=case_id,
        item_id=item_id2,
        significance="warn",
        cve_ids=[],
        in_kev=False,
        crime_type=None,
        attribution=None,
        attribution_confidence=None,
        damaged_party_sector=None,
        damaged_party_country=None,
        event_at=_iso(),
        iocs=[],
    )

    case = await db_module.get_case_by_id(db_conn, case_id)
    assert case["cvss_max"] == 7.5
    assert case["epss_max"] == 0.2


@pytest.mark.asyncio
async def test_cve_meta_upsert_and_get(db_conn):
    await db_module.upsert_cve_meta(db_conn, [
        {
            "cve_id": "CVE-2024-1",
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "cwe_ids": ["CWE-79"],
            "epss": 0.5,
            "fetched_at": _iso(),
        }
    ])
    meta = await db_module.get_cve_meta(db_conn, ["CVE-2024-1", "CVE-2024-999"])
    assert "CVE-2024-999" not in meta
    assert meta["CVE-2024-1"]["cvss_score"] == 9.8
    assert meta["CVE-2024-1"]["cwe_ids"] == ["CWE-79"]


@pytest.mark.asyncio
async def test_cve_meta_upsert_refreshes_existing_row(db_conn):
    await db_module.upsert_cve_meta(db_conn, [
        {"cve_id": "CVE-2024-1", "cvss_score": 5.0, "cvss_severity": "MEDIUM",
         "cwe_ids": [], "epss": 0.1, "fetched_at": _iso()},
    ])
    await db_module.upsert_cve_meta(db_conn, [
        {"cve_id": "CVE-2024-1", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
         "cwe_ids": ["CWE-79"], "epss": 0.9, "fetched_at": _iso()},
    ])
    meta = await db_module.get_cve_meta(db_conn, ["CVE-2024-1"])
    assert meta["CVE-2024-1"]["cvss_score"] == 9.8
    assert meta["CVE-2024-1"]["cwe_ids"] == ["CWE-79"]
