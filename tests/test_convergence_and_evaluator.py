"""Convergence pruning (target source count) and agent/human feedback
blending — see settings.source_target_count, research/heal.py's
_convergence_prune, and sources/value.py's origin-aware _component_feedback.
"""
import yaml

import pytest

from cybercrime_monitor import db as db_module
from cybercrime_monitor import health
from cybercrime_monitor.research import heal
from cybercrime_monitor.scheduler import load_sources
from cybercrime_monitor.settings import settings as app_settings
from cybercrime_monitor.sources import value as source_value


def _make_source(i: int, *, enabled: bool = True) -> dict:
    return {
        "id": f"src_{i}",
        "name": f"Source {i}",
        "type": "rss",
        "url": f"https://example.com/feed_{i}.xml",
        "interval_seconds": 900,
        "enabled": enabled,
    }


@pytest.mark.asyncio
async def test_convergence_prune_trims_lowest_scoring_sources_over_target(db_conn, tmp_path, monkeypatch):
    # 5 enabled sources, target=3 with a deadband of 0 -> 2 should be pruned.
    n = 5
    sources = [_make_source(i) for i in range(n)]
    path = tmp_path / "sources.yaml"
    path.write_text(yaml.safe_dump({"sources": sources}))

    monkeypatch.setattr(app_settings, "sources_config", path)
    monkeypatch.setattr(app_settings, "source_autoapply_enabled", True)
    monkeypatch.setattr(app_settings, "source_target_count", 3)
    monkeypatch.setattr(app_settings, "source_target_band", 0)

    # Give every source enough run history to clear _min_history, and a
    # distinct score (ascending with index) so the two lowest are src_0/src_1.
    for i, src in enumerate(sources):
        health.record_run_start(src["id"])
        health.record_success(src["id"], items_fetched=5)
        await db_module.save_source_value(
            db_conn, source_id=src["id"], score=0.1 * (i + 1), classification="marginal", components={},
        )

    await heal._prune_pass(db_conn, scheduler=None, sse_broadcaster=None)

    remaining = {s["id"]: s["enabled"] for s in load_sources()}
    assert remaining["src_0"] is False
    assert remaining["src_1"] is False
    assert remaining["src_2"] is True
    assert remaining["src_3"] is True
    assert remaining["src_4"] is True

    proposals = await db_module.get_heal_proposals(db_conn, status="validated")
    convergence_proposals = [
        p for p in proposals
        if p["source_id"] in ("src_0", "src_1") and p.get("action") == "prune"
    ]
    assert len(convergence_proposals) == 2


@pytest.mark.asyncio
async def test_convergence_prune_noop_when_within_target_band(db_conn, tmp_path, monkeypatch):
    sources = [_make_source(i) for i in range(3)]
    path = tmp_path / "sources.yaml"
    path.write_text(yaml.safe_dump({"sources": sources}))

    monkeypatch.setattr(app_settings, "sources_config", path)
    monkeypatch.setattr(app_settings, "source_autoapply_enabled", True)
    monkeypatch.setattr(app_settings, "source_target_count", 3)
    monkeypatch.setattr(app_settings, "source_target_band", 3)

    for i, src in enumerate(sources):
        health.record_run_start(src["id"])
        health.record_success(src["id"], items_fetched=5)
        await db_module.save_source_value(
            db_conn, source_id=src["id"], score=0.1 * (i + 1), classification="marginal", components={},
        )

    await heal._prune_pass(db_conn, scheduler=None, sse_broadcaster=None)

    remaining = {s["id"]: s["enabled"] for s in load_sources()}
    assert all(remaining.values())


def test_component_feedback_discounts_agent_origin(monkeypatch):
    monkeypatch.setattr(app_settings, "feedback_agent_weight", 0.5)

    # Human says useful, agent says not_useful — human dominates (weight 1.0
    # vs 0.5), so the blended score should stay above 0.5.
    by_origin = {
        "human": {"useful": 1},
        "agent": {"not_useful": 1},
    }
    score = source_value._component_feedback(by_origin)
    assert score is not None
    assert score > 0.5

    # Agent-only feedback still produces a score (fills the gap when there's
    # no human signal at all).
    agent_only = {"agent": {"useful": 3, "noise": 1}}
    score2 = source_value._component_feedback(agent_only)
    assert score2 is not None
    assert 0.0 < score2 < 1.0


def test_bucket_counts_and_media_prior(monkeypatch):
    monkeypatch.setattr(
        app_settings, "media_kind_prior",
        {"darknet_forum": 1.0, "forensic": 0.85, "feed": 0.7, "press": 0.6, "blog": 0.55},
    )
    sources = [
        {"id": "a", "enabled": True, "region": "eu", "media_kind": "darknet_forum"},
        {"id": "b", "enabled": True, "region": "us", "media_kind": "press"},
        {"id": "c", "enabled": False, "region": "eu", "media_kind": "press"},  # disabled, excluded
        {"id": "d", "enabled": True},  # unclassified, excluded from bucket tallies
    ]
    buckets = source_value.bucket_counts(sources)
    assert buckets["region"] == {"eu": 1, "us": 1}
    assert buckets["media_kind"] == {"darknet_forum": 1, "press": 1}

    assert source_value._component_media_prior({"media_kind": "darknet_forum"}) == 1.0
    assert source_value._component_media_prior({}) is None

    # The lone darknet_forum source sits in a thinner overall slice than the
    # lone press source once both region+media_kind shares are considered.
    diversity_darknet = source_value._component_diversity(sources[0], buckets)
    diversity_unclassified = source_value._component_diversity({"id": "d"}, buckets)
    assert diversity_unclassified is None
    assert diversity_darknet is not None


def test_bucket_counts_and_components_ignore_invalid_values():
    # A typo'd region/media_kind (hand-edited sources.yaml isn't validated on
    # load) must not silently skew the bucket tallies, get a media prior, or
    # earn a free maximal diversity bonus for being absent from every bucket.
    sources = [
        {"id": "a", "enabled": True, "region": "eu", "media_kind": "darknet_forum"},
        {"id": "typo", "enabled": True, "region": "europe", "media_kind": "forums"},
    ]
    buckets = source_value.bucket_counts(sources)
    assert buckets["region"] == {"eu": 1}
    assert buckets["media_kind"] == {"darknet_forum": 1}

    assert source_value._component_media_prior({"media_kind": "forums"}) is None
    assert source_value._component_diversity(
        {"id": "typo", "region": "europe", "media_kind": "forums"}, buckets
    ) is None


@pytest.mark.asyncio
async def test_add_feedback_with_agent_origin_and_aggregation(db_conn):
    # Set up a source-bearing item and a case-linked item, then write both
    # human and agent feedback and confirm aggregate_feedback_by_source
    # splits them by origin.
    await db_conn.execute(
        """INSERT INTO items (id, source_id, source_name, title, url, dedupe_key, seen_at)
           VALUES (1, 'src_x', 'Source X', 'title', 'https://x/1', 'dk1', :now)""",
        {"now": "2025-01-01T00:00:00+00:00"},
    )
    await db_conn.commit()

    await db_module.add_feedback(db_conn, case_id=None, item_id=1, verdict="useful", note=None, origin="human")
    await db_module.add_feedback(db_conn, case_id=None, item_id=1, verdict="noise", note="agent guess", origin="agent")

    agg = await db_module.aggregate_feedback_by_source(db_conn, since_iso="2000-01-01T00:00:00+00:00")
    assert agg["src_x"]["human"] == {"useful": 1}
    assert agg["src_x"]["agent"] == {"noise": 1}

    with pytest.raises(ValueError):
        await db_module.add_feedback(db_conn, case_id=None, item_id=1, verdict="useful", note=None, origin="bogus")
