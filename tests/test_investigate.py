"""Targeted-investigation pipeline (research/investigate.py) — the
investigator-submitted-brief feature that replaced the Keywords tab. Covers
the two outcomes that matter most: a confident match gets fully integrated
(item + extraction + case via the normal correlator), and an unconvincing
result creates nothing."""
import pytest

from cybercrime_monitor import db as db_module
from cybercrime_monitor.api.sse import broadcaster
from cybercrime_monitor.hermes.runner import HermesResult
from cybercrime_monitor.research import investigate
from cybercrime_monitor.settings import settings as app_settings


@pytest.fixture(autouse=True)
def _investigate_enabled(monkeypatch):
    monkeypatch.setattr(app_settings, "hermes_investigate_interval_seconds", 900)
    monkeypatch.setattr(app_settings, "investigate_min_confidence", 0.5)


async def _stub_run_agent_factory(data: dict | None, *, ok: bool = True):
    async def _stub(prompt, *, toolsets=None, timeout=None, model=None):
        return HermesResult(ok=ok, text="", data=data, error=None if ok else "stub failure", duration_seconds=0.1)
    return _stub


@pytest.mark.asyncio
async def test_no_match_creates_nothing(db_conn, monkeypatch):
    monkeypatch.setattr(
        investigate, "run_agent",
        await _stub_run_agent_factory({"found": False, "confidence": 0.1, "items": [], "new_feeds": []}),
    )

    inv_id = await db_module.create_investigation(db_conn, brief="Suspected breach of Acme Corp")
    inv = await db_module.get_investigation(db_conn, inv_id)
    await investigate._investigate_one(db_conn, inv, scheduler=None, sse_broadcaster=broadcaster)

    result = await db_module.get_investigation(db_conn, inv_id)
    assert result["status"] == "no_match"
    assert result["case_id"] is None

    items = await db_module.fetch_items(db_conn, limit=10)
    assert items == []


@pytest.mark.asyncio
async def test_confident_match_creates_item_and_case(db_conn, monkeypatch):
    data = {
        "found": True,
        "confidence": 0.9,
        "title": "Acme Corp ransomware breach",
        "crime_type": "ransomware",
        "victim": "Acme Corp",
        "victim_sector": "manufacturing",
        "victim_country": "US",
        "attribution": "ShadowGroup",
        "summary": "ShadowGroup claims to have breached Acme Corp and leaked data.",
        "cve_ids": [],
        "iocs": ["acme-leak.example.onion"],
        "items": [
            {
                "title": "ShadowGroup leak-site post: Acme Corp",
                "url": "https://example.com/leak/acme-corp",
                "snippet": "ShadowGroup posted Acme Corp data on their leak site.",
                "source_name": "ShadowGroup leak site",
                "published_at": None,
            }
        ],
        "new_feeds": [],
    }
    monkeypatch.setattr(investigate, "run_agent", await _stub_run_agent_factory(data))

    inv_id = await db_module.create_investigation(db_conn, brief="Acme Corp possibly hit by ShadowGroup ransomware")
    inv = await db_module.get_investigation(db_conn, inv_id)
    await investigate._investigate_one(db_conn, inv, scheduler=None, sse_broadcaster=broadcaster)

    result = await db_module.get_investigation(db_conn, inv_id)
    assert result["status"] == "completed"
    assert result["case_id"] is not None

    items = await db_module.fetch_items(db_conn, limit=10)
    assert len(items) == 1
    assert items[0]["source_id"] == "targeted_research"
    assert items[0]["victim"] == "Acme Corp"
    assert items[0]["classified"] is True

    case = await db_module.get_case_by_id(db_conn, result["case_id"])
    assert case is not None
    assert case["damaged_party"] == "Acme Corp"


@pytest.mark.asyncio
async def test_match_with_no_usable_items_falls_back_to_no_match(db_conn, monkeypatch):
    data = {"found": True, "confidence": 0.9, "items": [{"title": "", "url": "not-a-url"}], "new_feeds": []}
    monkeypatch.setattr(investigate, "run_agent", await _stub_run_agent_factory(data))

    inv_id = await db_module.create_investigation(db_conn, brief="Vague brief")
    inv = await db_module.get_investigation(db_conn, inv_id)
    await investigate._investigate_one(db_conn, inv, scheduler=None, sse_broadcaster=broadcaster)

    result = await db_module.get_investigation(db_conn, inv_id)
    assert result["status"] == "no_match"
    assert result["case_id"] is None


@pytest.mark.asyncio
async def test_confident_match_passes_new_feeds_to_discover(db_conn, monkeypatch):
    """Verifies the integration path: Hermes-returned feed candidates are handed
    to discover.py's existing validation/apply machinery (which we stub here to
    avoid real network probes in a unit test)."""
    from cybercrime_monitor.research import discover as discover_module

    candidate = {
        "name": "ACME News Feed",
        "kind": "rss",
        "feed_url": "https://example.com/rss.xml",
        "listing_url": None,
        "reason": "Reports on ACME breaches",
    }
    data = {
        "found": True,
        "confidence": 0.9,
        "title": "Acme Corp breach",
        "crime_type": "ransomware",
        "victim": "Acme Corp",
        "attribution": "ShadowGroup",
        "summary": "Breach summary",
        "cve_ids": [],
        "iocs": [],
        "items": [
            {
                "title": "Acme Corp breached",
                "url": "https://example.com/acme",
                "snippet": "...",
                "source_name": "ACME News",
                "published_at": None,
            }
        ],
        "new_feeds": [candidate],
    }
    monkeypatch.setattr(investigate, "run_agent", await _stub_run_agent_factory(data))

    called_with = []

    async def _fake_try_add(conn, cand, existing_domains, existing_ids, scheduler, sse_broadcaster):
        called_with.append(cand)

    monkeypatch.setattr(discover_module, "_try_add_candidate", _fake_try_add)

    inv_id = await db_module.create_investigation(db_conn, brief="Acme Corp breach")
    inv = await db_module.get_investigation(db_conn, inv_id)
    await investigate._investigate_one(db_conn, inv, scheduler=None, sse_broadcaster=broadcaster)

    result = await db_module.get_investigation(db_conn, inv_id)
    assert result["status"] == "completed"
    assert len(called_with) == 1
    assert called_with[0]["name"] == "ACME News Feed"


# ── API route tests ──────────────────────────────────────────────────────────
# These use the synchronous FastAPI TestClient; the DB fixture path is managed
# by conftest.py's client fixture.

ADMIN_TOKEN = "test-admin-token"


def test_api_create_investigation_requires_admin(client, monkeypatch):
    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)
    with client:
        resp = client.post("/api/investigations", json={"brief": "No token"})
        assert resp.status_code == 403

        resp = client.post(
            "/api/investigations",
            json={"brief": "Bad token"},
            headers={"X-Admin-Token": "wrong"},
        )
        assert resp.status_code == 403


def test_api_create_investigation_queues_and_nudges(client, monkeypatch):
    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)
    from cybercrime_monitor.api import routes as routes_module

    modified_jobs = []

    class _FakeScheduler:
        running = True

        def get_job(self, job_id):
            if job_id == "_investigate":
                return _FakeJob()
            return None

        def modify_job(self, job_id, *, next_run_time):
            modified_jobs.append((job_id, next_run_time))

    class _FakeJob:
        pass

    monkeypatch.setattr(routes_module, "load_sources", lambda: [])

    with client:
        client.app.state.scheduler = _FakeScheduler()
        resp = client.post(
            "/api/investigations",
            json={"brief": "Suspected breach of Acme Corp"},
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "queued"
        assert isinstance(data["investigation_id"], int)
        assert len(modified_jobs) == 1
        assert modified_jobs[0][0] == "_investigate"
        assert modified_jobs[0][1] is not None


def test_api_list_investigations_requires_admin(client, monkeypatch):
    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)
    with client:
        resp = client.get("/api/investigations")
        assert resp.status_code == 403

        resp = client.get("/api/investigations", headers={"X-Admin-Token": ADMIN_TOKEN})
        assert resp.status_code == 200
        assert "investigations" in resp.json()


def test_api_investigation_detail(client, monkeypatch):
    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)

    with client:
        resp = client.post(
            "/api/investigations",
            json={"brief": "Detail test"},
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
        inv_id = resp.json()["investigation_id"]

        resp = client.get(f"/api/investigations/{inv_id}", headers={"X-Admin-Token": ADMIN_TOKEN})
        assert resp.status_code == 200
        assert resp.json()["brief"] == "Detail test"

        resp = client.get("/api/investigations/99999", headers={"X-Admin-Token": ADMIN_TOKEN})
        assert resp.status_code == 404
