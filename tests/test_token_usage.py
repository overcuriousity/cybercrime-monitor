import asyncio
from datetime import datetime, timedelta, timezone

import aiosqlite
import pytest

from cybercrime_monitor import db as db_module
from cybercrime_monitor.hermes import usage_ingest
from cybercrime_monitor.settings import settings as app_settings


def _iso(seconds_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


# ── log_token_usage / burn_rate / token_timeseries round-trip ───────────────


@pytest.mark.asyncio
async def test_log_token_usage_feeds_burn_rate_totals(db_conn):
    await db_module.log_token_usage(
        db_conn, source="direct-llm", subsystem="classifier", model="gpt-test",
        input_tokens=100, output_tokens=50, cost_usd=0.01,
    )
    await db_module.log_token_usage(
        db_conn, source="direct-llm", subsystem="correlator", model="gpt-test",
        input_tokens=200, output_tokens=25, cost_usd=0.02,
    )

    burn = await db_module.burn_rate(db_conn, window_seconds=3600)
    assert burn["input_tokens"] == 300
    assert burn["output_tokens"] == 75
    assert burn["tokens_per_hour"] == pytest.approx(375.0)
    assert burn["cost_usd_per_hour"] == pytest.approx(0.03)
    # No source/model breakdown in the response (dropped — see db.burn_rate).
    assert "by_source" not in burn
    assert "by_model" not in burn


@pytest.mark.asyncio
async def test_burn_rate_excludes_rows_outside_window(db_conn):
    await db_module.log_token_usage(
        db_conn, source="direct-llm", model="m", input_tokens=10, output_tokens=10,
    )
    await db_conn.execute(
        "UPDATE token_usage SET ts = :ts", {"ts": _iso(7200)},
    )
    await db_conn.commit()

    burn = await db_module.burn_rate(db_conn, window_seconds=3600)
    assert burn["input_tokens"] == 0
    assert burn["output_tokens"] == 0
    assert burn["tokens_per_hour"] == 0


@pytest.mark.asyncio
async def test_burn_rate_cost_is_none_when_no_cost_reported(db_conn):
    await db_module.log_token_usage(
        db_conn, source="direct-llm", model="m", input_tokens=10, output_tokens=5, cost_usd=None,
    )
    burn = await db_module.burn_rate(db_conn, window_seconds=3600)
    assert burn["cost_usd_per_hour"] is None


@pytest.mark.asyncio
async def test_log_token_usage_never_raises_on_db_error(db_conn):
    await db_conn.close()
    # Connection is closed — log_token_usage must swallow the error, not raise.
    await db_module.log_token_usage(
        db_conn, source="direct-llm", model="m", input_tokens=1, output_tokens=1,
    )


@pytest.mark.asyncio
async def test_token_timeseries_buckets_by_time(db_conn):
    await db_module.log_token_usage(db_conn, source="direct-llm", model="m", input_tokens=10, output_tokens=0)
    await db_module.log_token_usage(db_conn, source="direct-llm", model="m", input_tokens=20, output_tokens=0)

    series = await db_module.token_timeseries(db_conn, window_seconds=3600, bucket_seconds=300)
    assert sum(b["tokens"] for b in series) == 30
    assert all("t" in b and "tokens" in b for b in series)


# ── upsert_hermes_token_usage idempotency / overlap ──────────────────────────


@pytest.mark.asyncio
async def test_upsert_hermes_token_usage_corrects_in_place(db_conn):
    ts = _iso()
    await db_module.upsert_hermes_token_usage(
        db_conn, session_id="sess-1", ts=ts, model="hermes-model",
        input_tokens=100, output_tokens=10,
    )
    await db_module.upsert_hermes_token_usage(
        db_conn, session_id="sess-1", ts=ts, model="hermes-model",
        input_tokens=500, output_tokens=50,
    )

    burn = await db_module.burn_rate(db_conn, window_seconds=3600)
    assert burn["input_tokens"] == 500
    assert burn["output_tokens"] == 50

    rows = await db_conn.execute_fetchall("SELECT COUNT(*) AS n FROM token_usage")
    assert rows[0]["n"] == 1


@pytest.mark.asyncio
async def test_upsert_hermes_token_usage_distinct_sessions_both_kept(db_conn):
    await db_module.upsert_hermes_token_usage(
        db_conn, session_id="sess-a", ts=_iso(), model="m", input_tokens=10, output_tokens=1,
    )
    await db_module.upsert_hermes_token_usage(
        db_conn, session_id="sess-b", ts=_iso(), model="m", input_tokens=20, output_tokens=2,
    )
    rows = await db_conn.execute_fetchall("SELECT COUNT(*) AS n FROM token_usage")
    assert rows[0]["n"] == 2


@pytest.mark.asyncio
async def test_max_ingested_hermes_started_at_tracks_high_water_mark(db_conn):
    assert await db_module.max_ingested_hermes_started_at(db_conn) is None

    older = _iso(1000)
    newer = _iso(10)
    await db_module.upsert_hermes_token_usage(
        db_conn, session_id="s1", ts=older, model="m", input_tokens=1, output_tokens=1,
    )
    await db_module.upsert_hermes_token_usage(
        db_conn, session_id="s2", ts=newer, model="m", input_tokens=1, output_tokens=1,
    )

    watermark = await db_module.max_ingested_hermes_started_at(db_conn)
    assert watermark == newer


# ── GET /api/tokens smoke test ───────────────────────────────────────────────


def test_api_tokens_route(client):
    async def _seed():
        conn = await db_module.open_db()
        await db_module.log_token_usage(
            conn, source="direct-llm", subsystem="classifier", model="m",
            input_tokens=42, output_tokens=8,
        )
        await conn.close()

    asyncio.run(_seed())

    with client:
        r = client.get("/api/tokens")
    assert r.status_code == 200
    data = r.json()
    assert "burn" in data and "timeseries" in data
    assert data["burn"]["input_tokens"] == 42
    assert data["burn"]["output_tokens"] == 8
    assert isinstance(data["timeseries"], list)


# ── usage_ingest.ingest_hermes_token_usage against a temp hermes state.db ───


async def _make_fake_hermes_db(path, sessions: list[dict]) -> None:
    conn = await aiosqlite.connect(str(path))
    await conn.executescript(
        """
        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            source TEXT,
            started_at REAL,
            model TEXT,
            input_tokens INTEGER,
            output_tokens INTEGER,
            cache_read_tokens INTEGER,
            cache_write_tokens INTEGER,
            estimated_cost_usd REAL,
            actual_cost_usd REAL
        )
        """
    )
    for s in sessions:
        await conn.execute(
            """INSERT INTO sessions
               (id, source, started_at, model, input_tokens, output_tokens,
                cache_read_tokens, cache_write_tokens, estimated_cost_usd, actual_cost_usd)
               VALUES (:id, :source, :started_at, :model, :input_tokens, :output_tokens,
                       :cache_read_tokens, :cache_write_tokens, :estimated_cost_usd, :actual_cost_usd)""",
            s,
        )
    await conn.commit()
    await conn.close()


def _session(
    id_, *, source="cli", started_at=None, model="hermes-model",
    input_tokens=100, output_tokens=10, cache_read_tokens=0, cache_write_tokens=0,
    estimated_cost_usd=None, actual_cost_usd=None,
):
    return {
        "id": id_,
        "source": source,
        "started_at": started_at if started_at is not None else datetime.now(timezone.utc).timestamp(),
        "model": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_tokens": cache_read_tokens,
        "cache_write_tokens": cache_write_tokens,
        "estimated_cost_usd": estimated_cost_usd,
        "actual_cost_usd": actual_cost_usd,
    }


@pytest.mark.asyncio
async def test_ingest_hermes_token_usage_copies_cli_sessions(db_conn, tmp_path, monkeypatch):
    fake_db = tmp_path / "hermes_state.db"
    await _make_fake_hermes_db(fake_db, [_session("h1", input_tokens=64228, output_tokens=2558)])
    monkeypatch.setattr(app_settings, "hermes_state_db_path", fake_db)

    ingested = await usage_ingest.ingest_hermes_token_usage(db_conn)
    assert ingested == 1

    burn = await db_module.burn_rate(db_conn, window_seconds=3600)
    assert burn["input_tokens"] == 64228
    assert burn["output_tokens"] == 2558


@pytest.mark.asyncio
async def test_ingest_hermes_token_usage_ignores_non_cli_sessions(db_conn, tmp_path, monkeypatch):
    fake_db = tmp_path / "hermes_state.db"
    await _make_fake_hermes_db(fake_db, [_session("h1", source="api", input_tokens=999, output_tokens=999)])
    monkeypatch.setattr(app_settings, "hermes_state_db_path", fake_db)

    ingested = await usage_ingest.ingest_hermes_token_usage(db_conn)
    assert ingested == 0


@pytest.mark.asyncio
async def test_ingest_hermes_token_usage_includes_output_only_sessions(db_conn, tmp_path, monkeypatch):
    """input_tokens + output_tokens > 0, not input_tokens alone — see
    usage_ingest's WHERE clause fix."""
    fake_db = tmp_path / "hermes_state.db"
    await _make_fake_hermes_db(fake_db, [_session("h1", input_tokens=0, output_tokens=5)])
    monkeypatch.setattr(app_settings, "hermes_state_db_path", fake_db)

    ingested = await usage_ingest.ingest_hermes_token_usage(db_conn)
    assert ingested == 1


@pytest.mark.asyncio
async def test_ingest_hermes_token_usage_missing_db_returns_zero(db_conn, tmp_path, monkeypatch):
    monkeypatch.setattr(app_settings, "hermes_state_db_path", tmp_path / "does-not-exist.db")

    ingested = await usage_ingest.ingest_hermes_token_usage(db_conn)
    assert ingested == 0


@pytest.mark.asyncio
async def test_ingest_hermes_token_usage_is_idempotent_across_polls(db_conn, tmp_path, monkeypatch):
    fake_db = tmp_path / "hermes_state.db"
    started_at = (datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp()
    await _make_fake_hermes_db(fake_db, [_session("h1", started_at=started_at, input_tokens=10, output_tokens=2)])
    monkeypatch.setattr(app_settings, "hermes_state_db_path", fake_db)

    await usage_ingest.ingest_hermes_token_usage(db_conn)

    # Simulate the session still being in progress: counts grow on the next poll.
    conn = await aiosqlite.connect(str(fake_db))
    await conn.execute(
        "UPDATE sessions SET input_tokens = 50, output_tokens = 9 WHERE id = 'h1'"
    )
    await conn.commit()
    await conn.close()

    ingested = await usage_ingest.ingest_hermes_token_usage(db_conn)
    assert ingested == 1

    rows = await db_conn.execute_fetchall("SELECT COUNT(*) AS n FROM token_usage")
    assert rows[0]["n"] == 1
    burn = await db_module.burn_rate(db_conn, window_seconds=3600)
    assert burn["input_tokens"] == 50
    assert burn["output_tokens"] == 9
