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
async def test_find_candidate_cases_matches_shared_ioc(db_conn):
    """A shared IoC (e.g. a hash/onion address from a technical write-up)
    should surface a case as a fuzzy-merge candidate even when neither
    victim nor actor nor any CVE matches — see pipeline/correlate.py's
    _try_fuzzy_merge, which now passes iocs through to find_candidate_cases."""
    await _make_case(
        db_conn, days_ago=1, title="known-incident",
        damaged_party="UnrelatedVictim", attribution="UnrelatedActor",
        iocs=["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"],
    )

    since_iso = _iso(7)
    candidates = await db_module.find_candidate_cases(
        db_conn,
        victim="SomeoneElse",
        actor="SomeoneElseActor",
        cve_ids=[],
        iocs=["9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"],
        since_iso=since_iso,
    )
    assert [c["title"] for c in candidates] == ["known-incident"]


@pytest.mark.asyncio
async def test_find_candidate_cases_no_match_without_shared_signal(db_conn):
    await _make_case(
        db_conn, days_ago=1, title="known-incident",
        damaged_party="UnrelatedVictim", attribution="UnrelatedActor",
        iocs=["somehash"],
    )

    since_iso = _iso(7)
    candidates = await db_module.find_candidate_cases(
        db_conn, victim="SomeoneElse", actor="SomeoneElseActor", cve_ids=[],
        iocs=["differenthash"], since_iso=since_iso,
    )
    assert candidates == []


@pytest.mark.asyncio
async def test_find_candidate_cases_fuzzy_victim_bracket_suffix(db_conn):
    await _make_case(
        db_conn, days_ago=1, title="v-bank-base",
        damaged_party="V-Bank",
    )

    since_iso = _iso(7)
    candidates = await db_module.find_candidate_cases(
        db_conn, victim="V-Bank (Munich)", actor=None, cve_ids=[], iocs=None, since_iso=since_iso,
    )
    assert [c["title"] for c in candidates] == ["v-bank-base"]


@pytest.mark.asyncio
async def test_find_candidate_cases_fuzzy_victim_no_false_positives(db_conn):
    await _make_case(
        db_conn, days_ago=1, title="other-bank",
        damaged_party="OtherBank",
    )

    since_iso = _iso(7)
    candidates = await db_module.find_candidate_cases(
        db_conn, victim="V-Bank", actor=None, cve_ids=[], iocs=None, since_iso=since_iso,
    )
    assert candidates == []


@pytest.mark.asyncio
async def test_merge_cases_moves_items_and_updates_aggregates(db_conn):
    keep = await _make_case(
        db_conn, days_ago=2, title="V-Bank",
        damaged_party="V-Bank", significance="warn",
        cve_ids=["CVE-2024-1"],
    )
    drop = await _make_case(
        db_conn, days_ago=1, title="V-Bank (Munich)",
        damaged_party="V-Bank (Munich)", significance="critical",
        cve_ids=["CVE-2024-2"],
    )

    merged = await db_module.merge_cases(db_conn, keep_case_id=keep, drop_case_id=drop)

    assert merged["damaged_party"] == "V-Bank (Munich)"
    assert merged["title"] == "V-Bank (Munich)"
    assert merged["significance"] == "critical"
    assert set(json.loads(merged["cve_ids"])) == {"CVE-2024-1", "CVE-2024-2"}

    # drop case is gone
    assert await db_module.get_case_by_id(db_conn, drop) is None

    # all items now belong to the surviving case
    keep_items = await db_module.get_case_items(db_conn, keep)
    assert len(keep_items) == 2


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


async def _add_run(conn, case_id: int, *, status: str, hours_ago: float):
    run_id = await db_module.start_research_run(conn, case_id=case_id, model=None)
    await conn.execute(
        "UPDATE research_runs SET started_at = :ts WHERE id = :id",
        {"ts": _iso(hours_ago / 24), "id": run_id},
    )
    await db_module.finish_research_run(
        conn, run_id=run_id, status=status, findings={}, sources=[], error=None
    )


@pytest.mark.asyncio
async def test_research_eligibility_failure_retry_applies_across_levels(db_conn):
    """A *failed* research run only blocks re-research for the much shorter
    research_failure_retry_hours, regardless of significance level — see
    db._research_eligibility_sql's docstring and the 2026-06-21 production
    incident that motivated this (a backend-side failure was locking cases
    out of research for a full cooldown with no answer ever produced)."""
    failed_recent = await _make_case(db_conn, significance="critical", title="failed 1h ago")
    failed_stale = await _make_case(db_conn, significance="critical", title="failed 3h ago")

    await _add_run(db_conn, failed_recent, status="failed", hours_ago=1)
    await _add_run(db_conn, failed_stale, status="failed", hours_ago=3)

    now = datetime.now(timezone.utc)  # default research_failure_retry_hours=2
    eligible_ids = {c["id"] for c in await db_module.get_cases_needing_research(db_conn, limit=10, now=now)}

    assert failed_recent not in eligible_ids  # within 2h failure cooldown -> blocked
    assert failed_stale in eligible_ids  # past the 2h failure cooldown -> eligible


@pytest.mark.asyncio
async def test_research_eligibility_info_researched_exactly_once(db_conn):
    """INFO cases are eligible iff they have zero completed runs ever — one
    pass, then never again automatically (token-economy goal)."""
    never_researched = await _make_case(db_conn, significance="info", title="fresh info")
    completed_once = await _make_case(db_conn, significance="info", title="already researched")
    failed_then_retryable = await _make_case(db_conn, significance="info", title="failed long ago")

    await _add_run(db_conn, completed_once, status="completed", hours_ago=100000)  # ages ago, still blocks
    await _add_run(db_conn, failed_then_retryable, status="failed", hours_ago=100)  # past failure retry

    now = datetime.now(timezone.utc)
    eligible_ids = {c["id"] for c in await db_module.get_cases_needing_research(db_conn, limit=10, now=now)}

    assert never_researched in eligible_ids
    assert completed_once not in eligible_ids  # one completed run -> never again
    assert failed_then_retryable in eligible_ids  # only a failure on record -> still eligible


@pytest.mark.asyncio
async def test_research_eligibility_warn_weekly_cadence(db_conn):
    recent = await _make_case(db_conn, significance="warn", title="researched 3 days ago")
    stale = await _make_case(db_conn, significance="warn", title="researched 8 days ago")

    await _add_run(db_conn, recent, status="completed", hours_ago=3 * 24)
    await _add_run(db_conn, stale, status="completed", hours_ago=8 * 24)

    now = datetime.now(timezone.utc)  # default research_warn_interval_seconds=604800 (7d)
    eligible_ids = {c["id"] for c in await db_module.get_cases_needing_research(db_conn, limit=10, now=now)}

    assert recent not in eligible_ids
    assert stale in eligible_ids


@pytest.mark.asyncio
async def test_research_eligibility_critical_daily_cadence(db_conn):
    recent = await _make_case(db_conn, significance="critical", title="researched 12h ago")
    stale = await _make_case(db_conn, significance="critical", title="researched 30h ago")

    await _add_run(db_conn, recent, status="completed", hours_ago=12)
    await _add_run(db_conn, stale, status="completed", hours_ago=30)

    now = datetime.now(timezone.utc)  # default research_critical_interval_seconds=86400 (1d)
    eligible_ids = {c["id"] for c in await db_module.get_cases_needing_research(db_conn, limit=10, now=now)}

    assert recent not in eligible_ids
    assert stale in eligible_ids


@pytest.mark.asyncio
async def test_research_eligibility_forced_bypasses_everything_and_sorts_first(db_conn):
    blocked_critical = await _make_case(db_conn, significance="critical", title="researched 1h ago")
    await _add_run(db_conn, blocked_critical, status="completed", hours_ago=1)
    await db_module.request_case_research(db_conn, case_id=blocked_critical)

    await _make_case(db_conn, significance="critical", title="never researched")

    now = datetime.now(timezone.utc)
    eligible = await db_module.get_cases_needing_research(db_conn, limit=10, now=now)
    eligible_ids = [c["id"] for c in eligible]

    assert blocked_critical in eligible_ids  # forced bypasses the daily cooldown
    assert eligible_ids[0] == blocked_critical  # forced sorts first


@pytest.mark.asyncio
async def test_research_eligibility_orders_critical_before_warn_before_info(db_conn):
    info_case = await _make_case(db_conn, significance="info", title="info", days_ago=3)
    warn_case = await _make_case(db_conn, significance="warn", title="warn", days_ago=2)
    critical_case = await _make_case(db_conn, significance="critical", title="critical", days_ago=1)

    now = datetime.now(timezone.utc)
    eligible = await db_module.get_cases_needing_research(db_conn, limit=10, now=now)
    eligible_ids = [c["id"] for c in eligible]

    assert eligible_ids.index(critical_case) < eligible_ids.index(warn_case) < eligible_ids.index(info_case)


@pytest.mark.asyncio
async def test_count_cases_needing_research_matches_get_for_same_now(db_conn):
    """Drift canary: count_cases_needing_research must always agree with
    len(get_cases_needing_research(...)) for the same `now` — they share
    db._research_eligibility_sql by construction."""
    await _make_case(db_conn, significance="critical", title="c1")
    await _make_case(db_conn, significance="warn", title="c2")
    await _make_case(db_conn, significance="info", title="c3")
    blocked = await _make_case(db_conn, significance="info", title="c4 blocked")
    await _add_run(db_conn, blocked, status="completed", hours_ago=1)

    now = datetime.now(timezone.utc)
    eligible = await db_module.get_cases_needing_research(db_conn, limit=100, now=now)
    count = await db_module.count_cases_needing_research(db_conn, now=now)
    assert count == len(eligible)


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


ADMIN_TOKEN = "test-admin-token"


async def _seed_two_cases(db_path: str):
    app_settings.db_path = db_path
    conn = await db_module.open_db()
    keep_item = await _insert_item(conn)
    keep = await _create_case(
        conn, keep_item,
        case_key="keep-key",
        title="keep-base",
        damaged_party="V-Bank",
        significance="warn",
        cve_ids=["CVE-2024-1"],
        event_at=_iso(2),
    )
    drop_item = await _insert_item(conn)
    drop = await _create_case(
        conn, drop_item,
        case_key="drop-key",
        title="drop-specific",
        damaged_party="V-Bank (Munich)",
        significance="critical",
        cve_ids=["CVE-2024-2"],
        event_at=_iso(1),
    )
    await conn.close()
    return keep, drop


def test_api_merge_cases_requires_admin(client, monkeypatch):
    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)
    keep, drop = asyncio.run(_seed_two_cases(app_settings.db_path))

    with client:
        r = client.post(f"/api/cases/{keep}/merge/{drop}")
    assert r.status_code == 403

    with client:
        r = client.post(
            f"/api/cases/{keep}/merge/{drop}",
            headers={"X-Admin-Token": "wrong"},
        )
    assert r.status_code == 403


def test_api_merge_cases_success(client, monkeypatch):
    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)
    keep, drop = asyncio.run(_seed_two_cases(app_settings.db_path))

    with client:
        r = client.post(
            f"/api/cases/{keep}/merge/{drop}",
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["merged"] is True
    assert data["case_id"] == keep
    assert data["dropped_case_id"] == drop

    # Verify the surviving case via the detail endpoint.
    with client:
        r = client.get(f"/api/cases/{keep}")
    assert r.status_code == 200
    detail = r.json()
    assert detail["case"]["damaged_party"] == "V-Bank (Munich)"
    assert detail["case"]["significance"] == "critical"
    assert len(detail["items"]) == 2
