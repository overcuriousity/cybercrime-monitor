import hashlib
import time
from datetime import datetime, timedelta, timezone

import pytest

from cybercrime_monitor import db as db_module
from cybercrime_monitor.settings import settings as app_settings

ADMIN_TOKEN = "test-admin-token"


def _iso(seconds_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


async def _seed_case(conn, *, case_key: str = "case-1", title: str = "Test case") -> int:
    cur = await conn.execute(
        """
        INSERT INTO cases (case_key, title, first_seen, last_seen)
        VALUES (:case_key, :title, :ts, :ts)
        """,
        {"case_key": case_key, "title": title, "ts": _iso()},
    )
    await conn.commit()
    return cur.lastrowid


# ── db.py: accounts/bookmarks helpers ────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_and_get_account_by_hash(db_conn):
    account_id = await db_module.create_account(db_conn, token_hash="abc123")
    account = await db_module.get_account_by_hash(db_conn, "abc123")
    assert account is not None
    assert account["id"] == account_id
    assert account["is_admin"] == 0

    assert await db_module.get_account_by_hash(db_conn, "nope") is None


@pytest.mark.asyncio
async def test_ensure_admin_account_idempotent(db_conn):
    first = await db_module.ensure_admin_account(db_conn, "admin-hash")
    assert first["is_admin"] == 1

    second = await db_module.ensure_admin_account(db_conn, "admin-hash")
    assert second["id"] == first["id"]

    rows = await db_conn.execute_fetchall("SELECT COUNT(*) AS n FROM accounts")
    assert rows[0]["n"] == 1


@pytest.mark.asyncio
async def test_bookmark_add_remove_and_list(db_conn):
    account_id = await db_module.create_account(db_conn, token_hash="u1")
    case_a = await _seed_case(db_conn, case_key="a")
    case_b = await _seed_case(db_conn, case_key="b")

    await db_module.add_bookmark(db_conn, account_id=account_id, case_id=case_a)
    await db_module.add_bookmark(db_conn, account_id=account_id, case_id=case_b)
    # Re-adding the same bookmark is a no-op (INSERT OR IGNORE), not an error.
    await db_module.add_bookmark(db_conn, account_id=account_id, case_id=case_a)

    ids = set(await db_module.get_bookmarked_case_ids(db_conn, account_id))
    assert ids == {case_a, case_b}

    await db_module.remove_bookmark(db_conn, account_id=account_id, case_id=case_a)
    ids = set(await db_module.get_bookmarked_case_ids(db_conn, account_id))
    assert ids == {case_b}


@pytest.mark.asyncio
async def test_bookmark_cascades_when_case_deleted(db_conn):
    account_id = await db_module.create_account(db_conn, token_hash="u1")
    case_id = await _seed_case(db_conn)
    await db_module.add_bookmark(db_conn, account_id=account_id, case_id=case_id)

    await db_conn.execute("DELETE FROM cases WHERE id = :id", {"id": case_id})
    await db_conn.commit()

    assert await db_module.get_bookmarked_case_ids(db_conn, account_id) == []


@pytest.mark.asyncio
async def test_fetch_cases_bookmarked_by_filter(db_conn):
    account_id = await db_module.create_account(db_conn, token_hash="u1")
    case_a = await _seed_case(db_conn, case_key="a", title="Bookmarked one")
    await _seed_case(db_conn, case_key="b", title="Not bookmarked")
    await db_module.add_bookmark(db_conn, account_id=account_id, case_id=case_a)

    cases = await db_module.fetch_cases(db_conn, bookmarked_by=account_id)
    assert [c["id"] for c in cases] == [case_a]

    total = await db_module.count_cases(db_conn, bookmarked_by=account_id)
    assert total == 1

    # No filter at all (bookmarked_by=None) returns everything.
    all_cases = await db_module.fetch_cases(db_conn)
    assert len(all_cases) == 2


@pytest.mark.asyncio
async def test_prune_expired_accounts_keeps_admin_and_fresh(db_conn):
    stale_id = await db_module.create_account(db_conn, token_hash="stale")
    fresh_id = await db_module.create_account(db_conn, token_hash="fresh")
    admin_id = await db_module.create_account(db_conn, token_hash="admin", is_admin=True)

    # Backdate the stale and admin accounts' last_seen_at well past the cutoff.
    old_ts = _iso(10_000_000)
    await db_conn.execute(
        "UPDATE accounts SET last_seen_at = :ts WHERE id IN (:a, :b)",
        {"ts": old_ts, "a": stale_id, "b": admin_id},
    )
    await db_conn.commit()

    cutoff = _iso(1000)
    deleted = await db_module.prune_expired_accounts(db_conn, cutoff_iso=cutoff)
    assert deleted == 1

    assert await db_module.get_account_by_hash(db_conn, "stale") is None
    assert await db_module.get_account_by_hash(db_conn, "fresh") is not None
    assert await db_module.get_account_by_hash(db_conn, "admin") is not None


@pytest.mark.asyncio
async def test_prune_expired_accounts_cascades_bookmarks(db_conn):
    stale_id = await db_module.create_account(db_conn, token_hash="stale")
    case_id = await _seed_case(db_conn)
    await db_module.add_bookmark(db_conn, account_id=stale_id, case_id=case_id)
    await db_conn.execute(
        "UPDATE accounts SET last_seen_at = :ts WHERE id = :id", {"ts": _iso(10_000_000), "id": stale_id}
    )
    await db_conn.commit()

    await db_module.prune_expired_accounts(db_conn, cutoff_iso=_iso(1000))

    rows = await db_conn.execute_fetchall("SELECT COUNT(*) AS n FROM bookmarks")
    assert rows[0]["n"] == 0


# ── routes.py: identity resolution + PoW ─────────────────────────────────────


@pytest.mark.asyncio
async def test_resolve_identity_roles(db_conn, monkeypatch):
    from cybercrime_monitor.api import routes as routes_module

    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)

    none_identity = await routes_module.resolve_identity(x_admin_token=None, db=db_conn)
    assert none_identity == {"role": "none", "account_id": None, "theme": None}

    admin_identity = await routes_module.resolve_identity(x_admin_token=ADMIN_TOKEN, db=db_conn)
    assert admin_identity["role"] == "admin"
    assert admin_identity["account_id"] is not None
    assert admin_identity["theme"] is None

    # The admin account is lazily provisioned and stable across calls.
    admin_identity_2 = await routes_module.resolve_identity(x_admin_token=ADMIN_TOKEN, db=db_conn)
    assert admin_identity_2["account_id"] == admin_identity["account_id"]

    bogus_identity = await routes_module.resolve_identity(x_admin_token="garbage", db=db_conn)
    assert bogus_identity == {"role": "none", "account_id": None, "theme": None}

    key_hash = hashlib.sha256(b"some-user-key").hexdigest()
    await db_module.create_account(db_conn, token_hash=key_hash)
    user_identity = await routes_module.resolve_identity(x_admin_token="some-user-key", db=db_conn)
    assert user_identity["role"] == "user"
    assert user_identity["theme"] is None


@pytest.mark.asyncio
async def test_require_user_rejects_none_role():
    from fastapi import HTTPException

    from cybercrime_monitor.api import routes as routes_module

    with pytest.raises(HTTPException) as exc_info:
        await routes_module.require_user(identity={"role": "none", "account_id": None})
    assert exc_info.value.status_code == 403

    # Both admin and user roles are accepted.
    result = await routes_module.require_user(identity={"role": "admin", "account_id": 1})
    assert result["role"] == "admin"


def _solve_pow(nonce: str, bits: int) -> str:
    """Test-only brute-force solver mirroring the client's solvePow loop."""
    counter = 0
    while True:
        candidate = str(counter)
        digest = hashlib.sha256(f"{nonce}:{candidate}".encode()).digest()
        leading = 0
        for byte in digest:
            if byte == 0:
                leading += 8
                continue
            leading += 8 - byte.bit_length()
            break
        if leading >= bits:
            return candidate
        counter += 1


def test_accounts_challenge_and_create_round_trip(client, monkeypatch):
    monkeypatch.setattr(app_settings, "account_pow_bits", 4)  # cheap to solve in a test
    with client:
        challenge = client.get("/api/accounts/challenge").json()
        assert challenge["bits"] == 4
        solution = _solve_pow(challenge["nonce"], challenge["bits"])
        resp = client.post("/api/accounts", json={**challenge, "solution": solution})
        assert resp.status_code == 200
        assert "access_key" in resp.json()
        assert len(resp.json()["access_key"]) > 20


def test_accounts_create_rejects_bad_solution(client, monkeypatch):
    monkeypatch.setattr(app_settings, "account_pow_bits", 8)
    with client:
        challenge = client.get("/api/accounts/challenge").json()
        resp = client.post("/api/accounts", json={**challenge, "solution": "not-a-real-solution"})
        assert resp.status_code == 400


def test_accounts_create_rejects_forged_signature(client, monkeypatch):
    monkeypatch.setattr(app_settings, "account_pow_bits", 4)
    with client:
        challenge = client.get("/api/accounts/challenge").json()
        solution = _solve_pow(challenge["nonce"], challenge["bits"])
        forged = {**challenge, "bits": 0, "solution": solution}  # tamper with difficulty
        resp = client.post("/api/accounts", json=forged)
        assert resp.status_code == 400


def test_accounts_create_rejects_expired_challenge(client, monkeypatch):
    monkeypatch.setattr(app_settings, "account_pow_bits", 4)
    with client:
        from cybercrime_monitor.api import routes as routes_module

        nonce = "fixed-nonce"
        bits = 4
        expired_at = int(time.time()) - 10
        sig = routes_module._pow_sign(nonce, bits, expired_at)
        solution = _solve_pow(nonce, bits)
        resp = client.post(
            "/api/accounts",
            json={"nonce": nonce, "bits": bits, "expires_at": expired_at, "sig": sig, "solution": solution},
        )
        assert resp.status_code == 400


# ── routes.py: bookmark endpoints ────────────────────────────────────────────


def test_bookmark_requires_valid_access_key(client, monkeypatch):
    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)
    with client:
        resp = client.post("/api/cases/1/bookmark")
        assert resp.status_code == 403

        resp = client.post("/api/cases/1/bookmark", headers={"X-Admin-Token": "wrong"})
        assert resp.status_code == 403


def test_bookmark_add_remove_via_api(client, monkeypatch):
    import asyncio

    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)

    async def _seed():
        conn = await db_module.open_db()
        case_id = await _seed_case(conn)
        await conn.close()
        return case_id

    case_id = asyncio.run(_seed())

    with client:
        resp = client.post(f"/api/cases/{case_id}/bookmark", headers={"X-Admin-Token": ADMIN_TOKEN})
        assert resp.status_code == 200

        listed = client.get("/api/cases", headers={"X-Admin-Token": ADMIN_TOKEN}).json()
        case = next(c for c in listed["cases"] if c["id"] == case_id)
        assert case["bookmarked"] is True

        only_bookmarked = client.get(
            "/api/cases?bookmarked=true", headers={"X-Admin-Token": ADMIN_TOKEN}
        ).json()
        assert [c["id"] for c in only_bookmarked["cases"]] == [case_id]

        resp = client.delete(f"/api/cases/{case_id}/bookmark", headers={"X-Admin-Token": ADMIN_TOKEN})
        assert resp.status_code == 200

        only_bookmarked = client.get(
            "/api/cases?bookmarked=true", headers={"X-Admin-Token": ADMIN_TOKEN}
        ).json()
        assert only_bookmarked["cases"] == []


def test_bookmark_only_filter_without_identity_returns_empty(client):
    with client:
        resp = client.get("/api/cases?bookmarked=true")
        assert resp.status_code == 200
        assert resp.json() == {"total": 0, "cases": [], "mode": "keyword"}


def test_bookmark_nonexistent_case_404s(client, monkeypatch):
    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)
    with client:
        resp = client.post("/api/cases/999999/bookmark", headers={"X-Admin-Token": ADMIN_TOKEN})
        assert resp.status_code == 404


# ── routes.py: /api/status auth.role ─────────────────────────────────────────


def test_status_reports_auth_role(client, monkeypatch):
    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)
    with client:
        resp = client.get("/api/status")
        assert resp.json()["auth"]["role"] == "none"

        resp = client.get("/api/status", headers={"X-Admin-Token": ADMIN_TOKEN})
        assert resp.json()["auth"]["role"] == "admin"

        resp = client.get("/api/status", headers={"X-Admin-Token": "wrong"})
        assert resp.json()["auth"]["role"] == "none"


# ── routes.py: theme endpoint ───────────────────────────────────────────────


def test_theme_requires_auth(client, monkeypatch):
    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)
    with client:
        resp = client.put("/api/account/theme", json={"theme": "light"})
        assert resp.status_code == 403

        resp = client.put(
            "/api/account/theme",
            json={"theme": "light"},
            headers={"X-Admin-Token": "wrong"},
        )
        assert resp.status_code == 403


def test_theme_validation_and_round_trip(client, monkeypatch):
    monkeypatch.setattr(app_settings, "admin_token", ADMIN_TOKEN)
    with client:
        # Invalid theme value
        resp = client.put(
            "/api/account/theme",
            json={"theme": "purple"},
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
        assert resp.status_code == 400

        # Set light
        resp = client.put(
            "/api/account/theme",
            json={"theme": "light"},
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
        assert resp.status_code == 200

        # Round-trip via /api/status
        resp = client.get("/api/status", headers={"X-Admin-Token": ADMIN_TOKEN})
        assert resp.json()["auth"]["theme"] == "light"

        # Set dark
        resp = client.put(
            "/api/account/theme",
            json={"theme": "dark"},
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
        assert resp.status_code == 200

        resp = client.get("/api/status", headers={"X-Admin-Token": ADMIN_TOKEN})
        assert resp.json()["auth"]["theme"] == "dark"
