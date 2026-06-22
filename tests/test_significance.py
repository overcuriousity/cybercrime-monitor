from datetime import datetime, timedelta, timezone

import pytest

from cybercrime_monitor import db as db_module
from cybercrime_monitor import significance as sig
from cybercrime_monitor.models import Item
from cybercrime_monitor.research.agent import _reconcile_verdict
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


async def _make_case(conn, *, days_ago: float = 0, **kwargs):
    item_id = await _insert_item(conn)
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
        significance_score=kwargs.get("significance_score", sig.significance_score(kwargs.get("significance", "warn"))),
        cve_ids=kwargs.get("cve_ids", []),
        in_kev=kwargs.get("in_kev", False),
        item_id=item_id,
        event_at=kwargs.get("event_at", _iso(days_ago)),
        iocs=kwargs.get("iocs", []),
    )


# ── significance.py pure functions ───────────────────────────────────────────


def test_max_significance_picks_higher_rank():
    assert sig.max_significance("info", "warn") == "warn"
    assert sig.max_significance("critical", "info") == "critical"
    assert sig.max_significance("warn", "warn") == "warn"


def test_degrade_steps_down_one_level_and_floors_at_info():
    assert sig.degrade("critical") == "warn"
    assert sig.degrade("warn") == "info"
    assert sig.degrade("info") == "info"


def test_significance_score_matches_rank_over_three():
    assert sig.significance_score("info") == pytest.approx(1 / 3)
    assert sig.significance_score("warn") == pytest.approx(2 / 3)
    assert sig.significance_score("critical") == pytest.approx(1.0)


# ── research/agent._reconcile_verdict ────────────────────────────────────────


def test_reconcile_verdict_critical_without_ongoing_downgrades_to_warn():
    assert _reconcile_verdict("critical", False) == "warn"


def test_reconcile_verdict_critical_with_ongoing_passes_through():
    assert _reconcile_verdict("critical", True) == "critical"


def test_reconcile_verdict_valid_non_critical_passes_through():
    assert _reconcile_verdict("warn", False) == "warn"
    assert _reconcile_verdict("info", False) == "info"


def test_reconcile_verdict_invalid_returns_none():
    assert _reconcile_verdict(None, True) is None
    assert _reconcile_verdict("urgent", True) is None
    assert _reconcile_verdict(123, True) is None


# ── db.apply_research_findings significance precedence ──────────────────────


@pytest.mark.asyncio
async def test_apply_research_findings_overwrites_significance_when_given(db_conn):
    case_id = await _make_case(db_conn, significance="critical")

    await db_module.apply_research_findings(
        db_conn, case_id=case_id, status="researching", attribution=None,
        damaged_party=None, summary_addendum=None, significance="info",
    )

    case = await db_module.get_case_by_id(db_conn, case_id)
    assert case["significance"] == "info"
    assert case["significance_score"] == pytest.approx(sig.significance_score("info"))


@pytest.mark.asyncio
async def test_apply_research_findings_leaves_significance_when_none(db_conn):
    case_id = await _make_case(db_conn, significance="critical")

    await db_module.apply_research_findings(
        db_conn, case_id=case_id, status="researching", attribution=None,
        damaged_party=None, summary_addendum=None, significance=None,
    )

    case = await db_module.get_case_by_id(db_conn, case_id)
    assert case["significance"] == "critical"


# ── merge-precedence guard (researcher owns the level after first research) ─


@pytest.mark.asyncio
async def test_merge_item_into_case_raises_significance_before_research(db_conn):
    case_id = await _make_case(db_conn, significance="info")
    new_item_id = await _insert_item(db_conn)

    await db_module.merge_item_into_case(
        db_conn, case_id=case_id, item_id=new_item_id, significance="critical",
        cve_ids=[], in_kev=False, crime_type=None, attribution=None,
        attribution_confidence=None, damaged_party_sector=None,
        damaged_party_country=None, event_at=_iso(),
    )

    case = await db_module.get_case_by_id(db_conn, case_id)
    assert case["significance"] == "critical"  # max-merge still applies pre-research


@pytest.mark.asyncio
async def test_merge_item_into_case_does_not_raise_significance_after_research(db_conn):
    case_id = await _make_case(db_conn, significance="critical")

    # Researcher degrades the case to info on a completed pass.
    await db_module.apply_research_findings(
        db_conn, case_id=case_id, status="researching", attribution=None,
        damaged_party=None, summary_addendum=None, significance="info",
    )
    run_id = await db_module.start_research_run(db_conn, case_id=case_id, model=None)
    await db_module.finish_research_run(
        db_conn, run_id=run_id, status="completed", findings={}, sources=[], error=None
    )

    new_item_id = await _insert_item(db_conn)
    await db_module.merge_item_into_case(
        db_conn, case_id=case_id, item_id=new_item_id, significance="critical",
        cve_ids=[], in_kev=False, crime_type=None, attribution=None,
        attribution_confidence=None, damaged_party_sector=None,
        damaged_party_country=None, event_at=_iso(),
    )

    case = await db_module.get_case_by_id(db_conn, case_id)
    assert case["significance"] == "info"  # post-research: item-merge no longer re-escalates


# ── run_significance_decay ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_decay_caps_critical_to_warn_after_one_stale_window(db_conn):
    window = app_settings.research_stale_window_seconds
    case_id = await _make_case(db_conn, significance="critical", days_ago=(window / 86400) + 1)

    n = await db_module.run_significance_decay(db_conn)
    assert n == 1
    case = await db_module.get_case_by_id(db_conn, case_id)
    assert case["significance"] == "warn"


@pytest.mark.asyncio
async def test_decay_caps_critical_to_info_after_two_stale_windows(db_conn):
    window = app_settings.research_stale_window_seconds
    case_id = await _make_case(db_conn, significance="critical", days_ago=(2 * window / 86400) + 1)

    n = await db_module.run_significance_decay(db_conn)
    assert n == 1
    case = await db_module.get_case_by_id(db_conn, case_id)
    assert case["significance"] == "info"


@pytest.mark.asyncio
async def test_decay_skips_case_actively_researched_within_window(db_conn):
    window = app_settings.research_stale_window_seconds
    case_id = await _make_case(db_conn, significance="critical", days_ago=(2 * window / 86400) + 1)

    run_id = await db_module.start_research_run(db_conn, case_id=case_id, model=None)
    await db_module.finish_research_run(
        db_conn, run_id=run_id, status="completed", findings={}, sources=[], error=None
    )

    n = await db_module.run_significance_decay(db_conn)
    assert n == 0
    case = await db_module.get_case_by_id(db_conn, case_id)
    assert case["significance"] == "critical"  # research owns the level, decay defers


@pytest.mark.asyncio
async def test_decay_leaves_fresh_cases_untouched(db_conn):
    case_id = await _make_case(db_conn, significance="critical", days_ago=0)
    n = await db_module.run_significance_decay(db_conn)
    assert n == 0
    case = await db_module.get_case_by_id(db_conn, case_id)
    assert case["significance"] == "critical"
