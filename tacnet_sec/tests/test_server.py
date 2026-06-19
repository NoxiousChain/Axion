"""
Integration tests for Tier-3 server security controls:
  - Account lockout after repeated login failures (AC-7)
  - Admin unlock endpoint
  - TOTP MFA enrolment and enforcement (IA-2(1))

Uses the same fixture pattern as test_correlator.py: directly manipulates
api_mod._API_KEY and api_mod.DB_PATH to avoid env-var timing issues and
inter-test state pollution.
"""

from __future__ import annotations

import time

import pytest

_TEST_API_KEY = "test-tier3-key"
_ADMIN_PW = "AdminPass123!"


@pytest.fixture
def api_mod_db(tmp_path, monkeypatch):
    import tacnet_sec.server.api as api_mod

    # Ensure init_db() — including the FastAPI startup handler — always seeds
    # the admin account with _ADMIN_PW regardless of what .env exports.
    monkeypatch.setenv("AXION_ADMIN_PASSWORD", _ADMIN_PW)

    db_path = str(tmp_path / "tier3.sqlite")
    api_mod.DB_PATH = db_path
    api_mod._API_KEY = _TEST_API_KEY
    api_mod.init_db()
    yield api_mod
    api_mod._API_KEY = None


def _login(client, username="admin", password=_ADMIN_PW, api_key=_TEST_API_KEY, otp=None):
    body = {"username": username, "password": password, "api_key": api_key}
    if otp is not None:
        body["otp"] = otp
    return client.post("/api/login", json=body)


def _admin_token(client) -> str:
    r = _login(client)
    assert r.status_code == 200, r.text
    return r.json()["token"]


# ---------------------------------------------------------------------------
# Account lockout (AC-7)
# ---------------------------------------------------------------------------

def test_lockout_triggers_after_max_failures(api_mod_db):
    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import create_token, hash_password

    # Create a fresh user to lock out.
    conn = api_mod_db._conn()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        ("lockme", hash_password("Password1!"), "analyst", time.time()),
    )
    conn.commit()
    conn.close()

    with TestClient(api_mod_db.app) as client:
        # 5 bad-password attempts.
        for _ in range(5):
            r = _login(client, username="lockme", password="wrong")
            assert r.status_code == 401

        # 6th attempt — account should now be locked.
        r = _login(client, username="lockme", password="wrong")
        assert r.status_code == 403
        assert "locked" in r.json()["detail"].lower()

        # Even correct password is rejected while locked.
        r = _login(client, username="lockme", password="Password1!")
        assert r.status_code == 403


def test_admin_unlock_clears_lockout(api_mod_db):
    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import create_token, hash_password

    conn = api_mod_db._conn()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        ("lockme2", hash_password("Password1!"), "analyst", time.time()),
    )
    # Pre-lock the account.
    conn.execute(
        "UPDATE users SET failed_login_count=5, locked_until=? WHERE username='lockme2'",
        (time.time() + 1800,),
    )
    conn.commit()
    conn.close()

    with TestClient(api_mod_db.app) as client:
        token = _admin_token(client)

        # Confirm locked.
        r = _login(client, username="lockme2", password="Password1!")
        assert r.status_code == 403

        # Admin unlocks.
        r = client.post(
            "/api/users/lockme2/unlock",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "unlocked"

        # Now login succeeds.
        r = _login(client, username="lockme2", password="Password1!")
        assert r.status_code == 200


def test_non_admin_cannot_unlock(api_mod_db):
    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import create_token, hash_password

    conn = api_mod_db._conn()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        ("operatorX", hash_password("Password1!"), "operator", time.time()),
    )
    conn.commit()
    conn.close()

    with TestClient(api_mod_db.app) as client:
        op_token = create_token("operatorX", _TEST_API_KEY)
        r = client.post(
            "/api/users/lockme2/unlock",
            headers={"Authorization": f"Bearer {op_token}"},
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# TOTP MFA (IA-2(1))
# ---------------------------------------------------------------------------

def test_totp_enrol_returns_secret_and_uri(api_mod_db):
    try:
        import pyotp  # noqa: F401
    except ImportError:
        pytest.skip("pyotp not installed")

    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import hash_password

    conn = api_mod_db._conn()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        ("mfauser", hash_password("Password1!"), "operator", time.time()),
    )
    conn.commit()
    conn.close()

    with TestClient(api_mod_db.app) as client:
        token = _admin_token(client)
        r = client.post(
            "/api/users/mfauser/totp",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "totp_secret" in data
        assert "provisioning_uri" in data
        assert "mfauser" in data["provisioning_uri"]


def test_totp_login_fails_without_otp(api_mod_db):
    try:
        import pyotp  # noqa: F401
    except ImportError:
        pytest.skip("pyotp not installed")

    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import hash_password
    import pyotp

    conn = api_mod_db._conn()
    secret = pyotp.random_base32()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at, totp_secret) VALUES (?,?,?,?,?)",
        ("mfauser2", hash_password("Password1!"), "operator", time.time(), secret),
    )
    conn.commit()
    conn.close()

    with TestClient(api_mod_db.app) as client:
        r = _login(client, username="mfauser2", password="Password1!")
        assert r.status_code == 401
        assert "mfa" in r.json()["detail"].lower()


def test_totp_login_succeeds_with_valid_otp(api_mod_db):
    try:
        import pyotp
    except ImportError:
        pytest.skip("pyotp not installed")

    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import hash_password

    secret = pyotp.random_base32()
    conn = api_mod_db._conn()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at, totp_secret) VALUES (?,?,?,?,?)",
        ("mfauser3", hash_password("Password1!"), "operator", time.time(), secret),
    )
    conn.commit()
    conn.close()

    with TestClient(api_mod_db.app) as client:
        otp = pyotp.TOTP(secret).now()
        r = _login(client, username="mfauser3", password="Password1!", otp=otp)
        assert r.status_code == 200, r.text


def test_totp_login_fails_with_wrong_otp(api_mod_db):
    try:
        import pyotp
    except ImportError:
        pytest.skip("pyotp not installed")

    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import hash_password

    secret = pyotp.random_base32()
    conn = api_mod_db._conn()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at, totp_secret) VALUES (?,?,?,?,?)",
        ("mfauser4", hash_password("Password1!"), "operator", time.time(), secret),
    )
    conn.commit()
    conn.close()

    with TestClient(api_mod_db.app) as client:
        r = _login(client, username="mfauser4", password="Password1!", otp="000000")
        assert r.status_code == 401


def test_totp_disable_allows_login_without_otp(api_mod_db):
    try:
        import pyotp
    except ImportError:
        pytest.skip("pyotp not installed")

    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import hash_password

    secret = pyotp.random_base32()
    conn = api_mod_db._conn()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at, totp_secret) VALUES (?,?,?,?,?)",
        ("mfauser5", hash_password("Password1!"), "operator", time.time(), secret),
    )
    conn.commit()
    conn.close()

    with TestClient(api_mod_db.app) as client:
        token = _admin_token(client)
        r = client.delete(
            "/api/users/mfauser5/totp",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

        r = _login(client, username="mfauser5", password="Password1!")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Bug-fix regressions
# ---------------------------------------------------------------------------

def test_delete_user_not_found(api_mod_db):
    """delete_user must return 404 when the username doesn't exist (was silently 200)."""
    from fastapi.testclient import TestClient

    with TestClient(api_mod_db.app) as client:
        token = _admin_token(client)
        r = client.delete(
            "/api/users/ghost_user_that_does_not_exist",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 404, r.text
        assert "not found" in r.json()["detail"].lower()


def test_delete_existing_user_succeeds(api_mod_db):
    """Sanity check: deleting a real user still returns 200."""
    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import hash_password

    conn = api_mod_db._conn()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        ("tobedeleted", hash_password("Password1!"), "analyst", time.time()),
    )
    conn.commit()
    conn.close()

    with TestClient(api_mod_db.app) as client:
        token = _admin_token(client)
        r = client.delete(
            "/api/users/tobedeleted",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "deleted"


def test_unlock_nonexistent_user_returns_404(api_mod_db):
    """unlock_user must return 404 for a username that doesn't exist."""
    from fastapi.testclient import TestClient

    with TestClient(api_mod_db.app) as client:
        token = _admin_token(client)
        r = client.post(
            "/api/users/nobody_here/unlock",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 404, r.text


def test_audit_hmac_uses_6_decimal_places(api_mod_db):
    """_audit_hmac must format ts as %.6f so Go and Python produce identical HMACs."""
    import hashlib
    import hmac as hmac_mod

    api_mod = api_mod_db
    ts = 1745000000.1  # has fewer than 6 decimal places when repr'd by Python

    result = api_mod._audit_hmac(ts, "alice", "login_success", None, None)

    # Recompute manually with the %.6f format
    key = hashlib.sha256(("axion-audit-v1:" + _TEST_API_KEY).encode()).digest()
    msg = f"{ts:.6f}|alice|login_success||".encode()
    expected = hmac_mod.new(key, msg, digestmod=hashlib.sha256).hexdigest()

    assert result == expected, (
        f"HMAC mismatch — ts formatting is not %.6f.\n"
        f"  got:      {result}\n"
        f"  expected: {expected}"
    )


def test_audit_hmac_not_using_repr_format(api_mod_db):
    """Ensure the old repr format (which drops trailing zeros) no longer matches."""
    import hashlib
    import hmac as hmac_mod

    api_mod = api_mod_db
    ts = 1745000000.1  # Python repr gives "1745000000.1" — only 1 decimal place

    result = api_mod._audit_hmac(ts, "alice", "login_success", None, None)

    # Old broken format: f"{ts}|..." (no fixed precision)
    key = hashlib.sha256(("axion-audit-v1:" + _TEST_API_KEY).encode()).digest()
    old_msg = f"{ts}|alice|login_success||".encode()
    old_hmac = hmac_mod.new(key, old_msg, digestmod=hashlib.sha256).hexdigest()

    # If ts has trailing zeros stripped, the formats differ — new HMAC must not match old
    if f"{ts}" != f"{ts:.6f}":
        assert result != old_hmac, "HMAC still uses repr format instead of %.6f"


def test_broadcast_iterates_snapshot(api_mod_db):
    """_broadcast must not raise RuntimeError when _ws_clients is modified mid-iteration."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    api_mod = api_mod_db

    # Build a fake WS that removes itself from _ws_clients when send_json is called
    class SelfRemovingWS:
        async def send_json(self, msg):
            if self in api_mod._ws_clients:
                api_mod._ws_clients.remove(self)

    ws1 = SelfRemovingWS()
    ws2 = AsyncMock()
    api_mod._ws_clients[:] = [ws1, ws2]

    # Must not raise RuntimeError: list changed size during iteration
    asyncio.get_event_loop().run_until_complete(api_mod._broadcast({"type": "alert"}))

    # ws2 must still have received the message
    ws2.send_json.assert_called_once()
    api_mod._ws_clients.clear()
