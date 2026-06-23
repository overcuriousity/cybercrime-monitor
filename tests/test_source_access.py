"""access axis (sources/value.py's access_for/is_structurally_empty) and the
degraded-source rotation gap it closes — see research/heal.py's _candidates
and _prune_pass. A scrape-access source that returns 200s but parses 0 items
for a sustained streak (selector drift / a captcha wall) used to be invisible
to both heal (only triggered on consecutive_errors) and prune (should_prune
required negative analyst feedback that never accrues on an unreviewed
source) — these tests pin down the fix: heal investigates it first, and
prune only rotates it out once heal has had a genuine chance.
"""
import pytest
import yaml

from cybercrime_monitor import db as db_module
from cybercrime_monitor import health
from cybercrime_monitor.research import heal
from cybercrime_monitor.scheduler import load_sources
from cybercrime_monitor.settings import settings as app_settings
from cybercrime_monitor.sources import value as source_value


def _scrape_source(sid="scraper_1", **overrides) -> dict:
    src = {
        "id": sid,
        "name": "Scraper One",
        "type": "html_forum",
        "url": "https://example.com/forum",
        "interval_seconds": 600,
        "enabled": True,
    }
    src.update(overrides)
    return src


# ── access_for / is_structurally_empty ──────────────────────────────────────

def test_access_for_uses_type_default_and_config_override():
    assert source_value.access_for({"type": "html_forum"}) == "scrape"
    assert source_value.access_for({"type": "tor_forum"}) == "scrape"
    assert source_value.access_for({"type": "rss"}) == "feed"
    assert source_value.access_for({"type": "nitter"}) == "feed"
    assert source_value.access_for({"type": "mastodon"}) == "api"
    assert source_value.access_for({"type": "hibp"}) == "api"
    assert source_value.access_for({"type": "ransomware_live"}) == "api"
    # paste defaults to scrape (pastebin's CSS-selector branch) but a
    # per-source override (e.g. rentry's JSON-API branch) wins.
    assert source_value.access_for({"type": "paste"}) == "scrape"
    assert source_value.access_for({"type": "paste", "access": "api"}) == "api"
    # unknown/missing type defaults to "feed" — the conservative choice.
    assert source_value.access_for({}) == "feed"


def test_is_structurally_empty_only_for_scrape_at_or_above_threshold(monkeypatch):
    monkeypatch.setattr(app_settings, "source_empty_streak_threshold", 5)
    scrape_src = _scrape_source()
    feed_src = {"id": "feed_1", "type": "rss"}

    below = health.SourceHealth(source_id="x", consecutive_empty=4)
    at = health.SourceHealth(source_id="x", consecutive_empty=5)
    above = health.SourceHealth(source_id="x", consecutive_empty=9)

    assert source_value.is_structurally_empty(scrape_src, below) is False
    assert source_value.is_structurally_empty(scrape_src, at) is True
    assert source_value.is_structurally_empty(scrape_src, above) is True
    # feed/api access is never structurally empty, no matter the streak.
    assert source_value.is_structurally_empty(feed_src, above) is False
    assert source_value.is_structurally_empty(scrape_src, None) is False


# ── _component_health decay ─────────────────────────────────────────────────

def test_component_health_decays_for_degraded_scrape_source(monkeypatch):
    monkeypatch.setattr(app_settings, "source_empty_streak_threshold", 5)
    sid = "scraper_health"
    health.record_run_start(sid)
    health.record_success(sid, items_fetched=0)
    for _ in range(8):
        health.record_success(sid, items_fetched=0)  # consecutive_empty -> 9

    src = _scrape_source(sid)
    score, ever_succeeded = source_value._component_health(src)
    assert ever_succeeded is True
    assert score is not None
    assert score < 0.5  # meaningfully decayed, not a perfect 1.0


def test_component_health_single_empty_tick_barely_moves_score():
    sid = "scraper_single_empty"
    health.record_run_start(sid)
    health.record_success(sid, items_fetched=0)  # consecutive_empty == 1

    src = _scrape_source(sid)
    score, _ = source_value._component_health(src)
    assert score == pytest.approx(1.0)


def test_component_health_feed_source_unaffected_by_empty_streak(monkeypatch):
    monkeypatch.setattr(app_settings, "source_empty_streak_threshold", 5)
    sid = "feed_health"
    health.record_run_start(sid)
    for _ in range(9):
        health.record_success(sid, items_fetched=0)

    src = {"id": sid, "type": "rss"}
    score, _ = source_value._component_health(src)
    assert score == pytest.approx(1.0)


# ── should_prune degraded branch ────────────────────────────────────────────

def test_should_prune_degraded_zero_contribution_regardless_of_feedback():
    value = {
        "classification": "marginal",
        "components": {"case_contribution": None},  # no feedback component at all
    }
    assert source_value.should_prune(value=value, min_history=True, degraded=True) is True


def test_should_prune_degraded_but_has_contribution_is_spared():
    value = {
        "classification": "marginal",
        "components": {"case_contribution": 0.4},
    }
    assert source_value.should_prune(value=value, min_history=True, degraded=True) is False


def test_should_prune_non_degraded_keeps_old_feedback_gated_behavior():
    value = {
        "classification": "marginal",
        "components": {"case_contribution": None, "feedback": None},
    }
    # No negative feedback recorded -> not pruned (pre-existing behavior).
    assert source_value.should_prune(value=value, min_history=True, degraded=False) is False

    value_negative = {
        "classification": "marginal",
        "components": {"case_contribution": None, "feedback": 0.2},
    }
    assert source_value.should_prune(value=value_negative, min_history=True, degraded=False) is True


def test_should_prune_respects_min_history_even_when_degraded():
    value = {"classification": "marginal", "components": {"case_contribution": None}}
    assert source_value.should_prune(value=value, min_history=False, degraded=True) is False


# ── media_kind widening / alias ──────────────────────────────────────────────

def test_legacy_feed_media_kind_aliases_to_threat_feed(monkeypatch):
    monkeypatch.setattr(
        app_settings, "media_kind_prior", {"threat_feed": 0.7, "darknet_forum": 1.0},
    )
    assert source_value._component_media_prior({"media_kind": "feed"}) == 0.7
    buckets = source_value.bucket_counts(
        [{"id": "a", "enabled": True, "media_kind": "feed"}]
    )
    assert buckets["media_kind"] == {"threat_feed": 1}


def test_new_media_kinds_are_valid():
    for kind in ("forum", "paste", "leak_site", "marketplace", "social", "breach_service"):
        assert kind in source_value.VALID_MEDIA_KINDS


# ── heal._candidates targets degraded scrape sources ────────────────────────

@pytest.mark.asyncio
async def test_heal_candidates_includes_degraded_scrape_source(db_conn, tmp_path, monkeypatch):
    path = tmp_path / "sources.yaml"
    src = _scrape_source()
    path.write_text(yaml.safe_dump({"sources": [src]}))
    monkeypatch.setattr(app_settings, "sources_config", path)
    monkeypatch.setattr(app_settings, "source_empty_streak_threshold", 5)

    health.record_run_start(src["id"])
    for _ in range(6):
        health.record_success(src["id"], items_fetched=0)
    assert health.get(src["id"]).consecutive_errors == 0  # not "broken" by the old signal

    candidates = await heal._candidates(db_conn)
    assert any(c["id"] == src["id"] for c in candidates)


@pytest.mark.asyncio
async def test_heal_candidates_excludes_quiet_feed_source(db_conn, tmp_path, monkeypatch):
    path = tmp_path / "sources.yaml"
    src = {"id": "feed_1", "name": "Feed", "type": "rss", "url": "https://x/feed.xml",
           "interval_seconds": 600, "enabled": True}
    path.write_text(yaml.safe_dump({"sources": [src]}))
    monkeypatch.setattr(app_settings, "sources_config", path)
    monkeypatch.setattr(app_settings, "source_empty_streak_threshold", 5)

    health.record_run_start(src["id"])
    for _ in range(9):
        health.record_success(src["id"], items_fetched=0)

    candidates = await heal._candidates(db_conn)
    assert not any(c["id"] == src["id"] for c in candidates)


# ── heal._prune_pass: degraded rotation gated on heal having tried ─────────

@pytest.mark.asyncio
async def test_prune_pass_spares_degraded_source_heal_has_not_investigated_yet(
    db_conn, tmp_path, monkeypatch
):
    path = tmp_path / "sources.yaml"
    src = _scrape_source()
    path.write_text(yaml.safe_dump({"sources": [src]}))
    monkeypatch.setattr(app_settings, "sources_config", path)
    monkeypatch.setattr(app_settings, "source_autoapply_enabled", True)
    monkeypatch.setattr(app_settings, "source_empty_streak_threshold", 5)

    health.record_run_start(src["id"])
    for _ in range(6):
        health.record_success(src["id"], items_fetched=0)

    await db_module.save_source_value(
        db_conn, source_id=src["id"], score=0.2, classification="marginal",
        components={"case_contribution": None},
    )

    # No heal proposal exists yet for this source -> "heal first" gate holds.
    await heal._prune_pass(db_conn, scheduler=None, sse_broadcaster=None)

    sources = {s["id"]: s["enabled"] for s in load_sources()}
    assert sources[src["id"]] is True


@pytest.mark.asyncio
async def test_prune_pass_rotates_degraded_source_after_heal_already_tried(
    db_conn, tmp_path, monkeypatch
):
    path = tmp_path / "sources.yaml"
    src = _scrape_source()
    path.write_text(yaml.safe_dump({"sources": [src]}))
    monkeypatch.setattr(app_settings, "sources_config", path)
    monkeypatch.setattr(app_settings, "source_autoapply_enabled", True)
    monkeypatch.setattr(app_settings, "source_empty_streak_threshold", 5)

    health.record_run_start(src["id"])
    for _ in range(6):
        health.record_success(src["id"], items_fetched=0)

    await db_module.save_source_value(
        db_conn, source_id=src["id"], score=0.2, classification="marginal",
        components={"case_contribution": None},
    )
    # Simulate a prior heal investigation that found no fix.
    await db_module.create_heal_proposal(
        db_conn, source_id=src["id"], proposal={}, notes="no fix found", action="heal",
    )

    await heal._prune_pass(db_conn, scheduler=None, sse_broadcaster=None)

    sources = {s["id"]: s["enabled"] for s in load_sources()}
    assert sources[src["id"]] is False


@pytest.mark.asyncio
async def test_prune_pass_spares_degraded_source_with_case_contribution(
    db_conn, tmp_path, monkeypatch
):
    path = tmp_path / "sources.yaml"
    src = _scrape_source()
    path.write_text(yaml.safe_dump({"sources": [src]}))
    monkeypatch.setattr(app_settings, "sources_config", path)
    monkeypatch.setattr(app_settings, "source_autoapply_enabled", True)
    monkeypatch.setattr(app_settings, "source_empty_streak_threshold", 5)

    health.record_run_start(src["id"])
    for _ in range(6):
        health.record_success(src["id"], items_fetched=0)

    await db_module.save_source_value(
        db_conn, source_id=src["id"], score=0.2, classification="marginal",
        components={"case_contribution": 0.6},  # has earned its keep before
    )
    await db_module.create_heal_proposal(
        db_conn, source_id=src["id"], proposal={}, notes="no fix found", action="heal",
    )

    await heal._prune_pass(db_conn, scheduler=None, sse_broadcaster=None)

    sources = {s["id"]: s["enabled"] for s in load_sources()}
    assert sources[src["id"]] is True
