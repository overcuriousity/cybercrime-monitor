"""Stale-source removal: a source disabled by hand (e.g. a `# needs: ...`
entry edited directly into sources.yaml, with no source_heal_proposals
history at all) used to sit disabled forever, because _maybe_remove_source
only ever read a disabled_at timestamp from a proposal the prune pass
itself had created. research/heal.py's _prune_pass now starts that clock
for ANY already-disabled source the first time it's observed, regardless
of who disabled it — these tests pin that behavior down.
"""
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from cybercrime_monitor import db as db_module
from cybercrime_monitor.research import heal
from cybercrime_monitor.scheduler import load_sources
from cybercrime_monitor.settings import settings as app_settings


def _write_sources_yaml(path, *, enabled: bool) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "sources": [
                    {
                        "id": "manually_disabled_src",
                        "name": "Manually Disabled Source",
                        "type": "rss",
                        "url": "https://example.com/feed.xml",
                        "interval_seconds": 900,
                        "enabled": enabled,
                    }
                ]
            }
        )
    )


@pytest.fixture
def sources_yaml(tmp_path, monkeypatch):
    path = tmp_path / "sources.yaml"
    _write_sources_yaml(path, enabled=False)
    monkeypatch.setattr(app_settings, "sources_config", path)
    monkeypatch.setattr(app_settings, "source_autoapply_enabled", True)
    monkeypatch.setattr(app_settings, "source_prune_grace_days", 5)
    return path


@pytest.mark.asyncio
async def test_prune_pass_starts_clock_for_hand_disabled_source(db_conn, sources_yaml):
    assert load_sources()[0]["enabled"] is False

    await heal._prune_pass(db_conn, scheduler=None, sse_broadcaster=None)

    # Still present and still disabled — grace period hasn't elapsed.
    sources = load_sources()
    assert len(sources) == 1
    assert sources[0]["enabled"] is False

    proposals = await db_module.get_heal_proposals(db_conn, status="validated")
    clock_proposals = [
        p for p in proposals
        if p["source_id"] == "manually_disabled_src" and p.get("action") == "prune" and p.get("applied")
    ]
    assert len(clock_proposals) == 1


@pytest.mark.asyncio
async def test_prune_pass_removes_hand_disabled_source_after_grace_period(db_conn, sources_yaml):
    # First pass starts the clock.
    await heal._prune_pass(db_conn, scheduler=None, sse_broadcaster=None)

    # Backdate the clock-start proposal past the (5-day) grace period.
    stale_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    await db_conn.execute(
        "UPDATE source_heal_proposals SET created_at = :ts WHERE source_id = 'manually_disabled_src'",
        {"ts": stale_ts},
    )
    await db_conn.commit()

    await heal._prune_pass(db_conn, scheduler=None, sse_broadcaster=None)

    sources = load_sources()
    assert sources == []


@pytest.mark.asyncio
async def test_prune_pass_leaves_enabled_sources_alone_without_value_data(db_conn, tmp_path, monkeypatch):
    path = tmp_path / "sources.yaml"
    _write_sources_yaml(path, enabled=True)
    monkeypatch.setattr(app_settings, "sources_config", path)
    monkeypatch.setattr(app_settings, "source_autoapply_enabled", True)

    await heal._prune_pass(db_conn, scheduler=None, sse_broadcaster=None)

    sources = load_sources()
    assert len(sources) == 1
    assert sources[0]["enabled"] is True
