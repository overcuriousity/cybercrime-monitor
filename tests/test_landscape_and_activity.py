import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from cybercrime_monitor import db as db_module
from cybercrime_monitor.models import Item
from cybercrime_monitor.settings import settings as app_settings


def _iso(days_offset: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_offset)).isoformat()


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


async def _create_case(conn, item_id: int, **kwargs):
    return await db_module.create_case(
        conn,
        case_key=kwargs.get("case_key", f"case-{item_id}"),
        title=kwargs.get("title", "Case title"),
        summary=kwargs.get("summary", "summary"),
        crime_type=kwargs.get("crime_type", "ransomware"),
        attribution=kwargs.get("attribution"),
        attribution_confidence=kwargs.get("attribution_confidence", 0.5),
        damaged_party=kwargs.get("damaged_party"),
        damaged_party_sector=kwargs.get("damaged_party_sector"),
        damaged_party_country=kwargs.get("damaged_party_country"),
        significance=kwargs.get("significance", "warn"),
        significance_score=kwargs.get("significance_score", 2.0),
        cve_ids=kwargs.get("cve_ids", []),
        in_kev=kwargs.get("in_kev", False),
        item_id=item_id,
        event_at=kwargs.get("event_at", _iso()),
        iocs=kwargs.get("iocs", []),
    )


async def _make_case(conn, *, days_ago: float = 0, **kwargs):
    item_id = await _insert_item(conn)
    return await _create_case(conn, item_id, event_at=_iso(days_ago), **kwargs)


# ── DB helper tests ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_count_cases_combines_since_iso_and_filters(db_conn):
    await _make_case(db_conn, days_ago=1, title="new critical", significance="critical")
    await _make_case(db_conn, days_ago=1, title="new warn", significance="warn")
    await _make_case(db_conn, days_ago=20, title="old critical", significance="critical")

    since_iso = _iso(7)
    assert await db_module.count_cases(db_conn, since_iso=since_iso, min_significance="critical") == 1
    assert await db_module.count_cases(db_conn, since_iso=since_iso, min_significance="warn") == 2
    assert await db_module.count_cases(db_conn, min_significance="critical") == 2


@pytest.mark.asyncio
async def test_fetch_cases_cve_ioc_filters_use_exact_json_match(db_conn):
    await _make_case(db_conn, days_ago=0, title="c1", cve_ids=["CVE-2024-1"], iocs=["hash1"])
    await _make_case(db_conn, days_ago=0, title="c2", cve_ids=["CVE-2024-100"], iocs=["hash2"])

    cve_results = await db_module.fetch_cases(db_conn, cve_id="CVE-2024-1")
    assert [c["title"] for c in cve_results] == ["c1"]

    ioc_results = await db_module.fetch_cases(db_conn, ioc="hash1")
    assert [c["title"] for c in ioc_results] == ["c1"]


@pytest.mark.asyncio
async def test_save_case_link_returns_new_then_existing(db_conn):
    a = await _make_case(db_conn, days_ago=0, title="case-a")
    b = await _make_case(db_conn, days_ago=0, title="case-b")

    is_new = await db_module.save_case_link(db_conn, case_a=a, case_b=b, score=0.9, reasons=["shared cve"])
    assert is_new is True

    is_new2 = await db_module.save_case_link(db_conn, case_a=a, case_b=b, score=0.95, reasons=["shared cve"])
    assert is_new2 is False

    links = await db_module.get_case_links(db_conn, a)
    assert len(links) == 1
    assert links[0]["score"] == pytest.approx(0.95)


@pytest.mark.asyncio
async def test_get_actor_profile_aggregates_over_all_cases(db_conn):
    await _make_case(
        db_conn,
        days_ago=2,
        title="p1",
        attribution="Actor1",
        damaged_party="Acme",
        damaged_party_sector="energy",
        damaged_party_country="US",
        cve_ids=["CVE-2024-1"],
    )
    await _make_case(
        db_conn,
        days_ago=1,
        title="p2",
        attribution="Actor1",
        damaged_party="Globex",
        damaged_party_sector="finance",
        damaged_party_country="DE",
        cve_ids=["CVE-2024-1", "CVE-2024-2"],
    )

    profile = await db_module.get_actor_profile(db_conn, "Actor1")
    assert profile["case_count"] == 2
    assert profile["victim_count"] == 2
    assert set(profile["sectors"]) == {"energy", "finance"}
    assert set(profile["countries"]) == {"DE", "US"}
    assert set(profile["cve_ids"]) == {"CVE-2024-1", "CVE-2024-2"}
    assert len(profile["activity"]) == 1
    assert profile["activity"][0]["n"] == 2


@pytest.mark.asyncio
async def test_log_ai_activity_roundtrips_and_serializes_details(db_conn):
    event = await db_module.log_ai_activity(
        db_conn,
        subsystem="classifier",
        action="batch_classified",
        summary="batch done",
        detail={"when": datetime.now(timezone.utc), "count": 3},
    )
    assert event["detail"]["count"] == 3
    assert isinstance(event["detail"]["when"], str)

    listed = await db_module.list_ai_activity(db_conn, limit=10)
    assert listed["total"] == 1
    assert listed["events"][0]["detail"]["count"] == 3


@pytest.mark.asyncio
async def test_prune_old_activity(db_conn):
    old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    new_ts = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    await db_module.log_ai_activity(db_conn, subsystem="heal", action="x", summary="old", detail={}, status="ok")
    # override ts of the just-inserted row to be old
    await db_conn.execute("UPDATE ai_activity SET ts = :ts WHERE summary = 'old'", {"ts": old_ts})
    await db_module.log_ai_activity(db_conn, subsystem="heal", action="x", summary="new", detail={}, status="ok")
    await db_conn.execute("UPDATE ai_activity SET ts = :ts WHERE summary = 'new'", {"ts": new_ts})
    await db_conn.commit()

    deleted = await db_module.prune_old_activity(db_conn, retention_days=5)
    assert deleted == 1
    remaining = await db_module.list_ai_activity(db_conn, limit=10)
    assert [e["summary"] for e in remaining["events"]] == ["new"]


@pytest.mark.asyncio
async def test_stats_trends_actor(db_conn):
    await _make_case(db_conn, days_ago=1, title="cur", attribution="ActorA")
    await _make_case(db_conn, days_ago=1, title="cur2", attribution="ActorA")
    await _make_case(db_conn, days_ago=10, title="prev", attribution="ActorA")
    await _make_case(db_conn, days_ago=10, title="prevB", attribution="ActorB")

    trends = await db_module.stats_trends(db_conn, dimension="actor", window_days=7, limit=10)
    by_actor = {t["value"]: t for t in trends}
    assert by_actor["ActorA"]["current"] == 2
    assert by_actor["ActorA"]["previous"] == 1
    assert by_actor["ActorA"]["status"] == "rising"
    assert by_actor["ActorB"]["status"] == "declining"


# ── Route tests ─────────────────────────────────────────────────────────────


async def _seed_single_case(db_path: str, **case_kwargs):
    app_settings.db_path = db_path
    conn = await db_module.open_db()
    item_id = await _insert_item(conn)
    case_id = await _create_case(conn, item_id, **case_kwargs)
    await conn.close()
    return case_id


def test_api_case_export_markdown_escapes_and_avoids_none(client):
    case_id = asyncio.run(
        _seed_single_case(
            app_settings.db_path,
            title="ACME _breach_ #1 [urgent]",
            summary="*Summary* with `code`",
            significance="critical",
            cve_ids=["CVE-2024-1"],
            iocs=["hash*1"],
            damaged_party="ACME",
            attribution="Actor1",
        )
    )

    with client:
        r = client.get(f"/api/cases/{case_id}/export?format=md")
    assert r.status_code == 200
    body = r.text
    assert "ACME \\_breach\\_ \\#1 \\[urgent\\]" in body
    assert "\\*Summary\\*" in body
    assert "`hash\\*1`" in body
    assert "First seen: None" not in body
    assert "Last seen: None" not in body


def test_api_actor_profile_route(client):
    asyncio.run(_seed_single_case(app_settings.db_path, title="actor-case", attribution="ActorRoute"))

    with client:
        r = client.get("/api/actors/ActorRoute")
    assert r.status_code == 200
    data = r.json()
    assert data["actor"] == "ActorRoute"
    assert data["case_count"] == 1


def test_api_landscape_export_all_time(client):
    asyncio.run(
        _seed_single_case(
            app_settings.db_path,
            title="landscape-case",
            significance="critical",
            in_kev=True,
        )
    )

    with client:
        r = client.get("/api/stats/landscape/export?all_time=1&trend_window_days=7")
    assert r.status_code == 200
    assert "landscape-case" in r.text or "Cases:" in r.text


def test_api_activity_route(client):
    async def _seed():
        conn = await db_module.open_db()
        await db_module.log_ai_activity(
            conn, subsystem="classifier", action="batch_classified", summary="test batch", detail={"n": 5}
        )
        await conn.close()

    asyncio.run(_seed())

    with client:
        r = client.get("/api/activity")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1
    assert any(e["summary"] == "test batch" for e in data["events"])
