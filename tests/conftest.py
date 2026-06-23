import pytest
import pytest_asyncio
from pathlib import Path
from cybercrime_monitor import db as db_module
from cybercrime_monitor.api.app import create_app
from cybercrime_monitor.settings import settings as app_settings


class _FakeScheduler:
    """Stand-in for APScheduler so route tests don't start background jobs."""

    running = True

    def start(self):
        pass

    def shutdown(self, wait=False):
        pass

    def get_job(self, job_id):
        return None

    def get_jobs(self):
        return []


@pytest_asyncio.fixture
async def db_conn(tmp_path):
    """Fresh, schema-initialised aiosqlite connection."""
    app_settings.db_path = tmp_path / "test.db"
    conn = await db_module.open_db()
    yield conn
    await conn.close()


@pytest.fixture
def client(monkeypatch, tmp_path):
    """FastAPI TestClient with a temp DB and a no-op scheduler."""
    app_settings.db_path = tmp_path / "test.db"
    import cybercrime_monitor.api.app as app_module

    monkeypatch.setattr(app_module, "build_scheduler", lambda db, broadcaster: _FakeScheduler())
    app = create_app()
    from fastapi.testclient import TestClient

    return TestClient(app)
