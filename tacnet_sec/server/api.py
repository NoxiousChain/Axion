
import argparse, asyncio, hashlib, hmac as _hmac_mod, json, os, pathlib, threading, time, logging, secrets
from typing import Any, Dict, List, Literal, Optional

try:
    import pyotp as _pyotp
    _PYOTP = True
except ImportError:
    _pyotp = None  # type: ignore[assignment]
    _PYOTP = False

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from . import correlator as _cor
from .auth import create_token, decode_token, hash_password, verify_password
from ..core import siem as _siem_mod

# ---------- SQLCipher (optional) ----------
# Encrypts the server SQLite DB at rest.
# Requires: apk add sqlcipher-dev && pip install sqlcipher3
# Set AXION_DB_KEY in server.env to enable. Leave empty for plain SQLite.
try:
    from sqlcipher3 import dbapi2 as _db_module
    _SQLCIPHER = True
except ImportError:
    import sqlite3 as _db_module  # type: ignore[no-redef]
    _SQLCIPHER = False

DB_PATH      = os.environ.get("TACNET_SERVER_DB", "server_alerts.sqlite")
MAX_BODY_BYTES = int(os.environ.get("AXION_MAX_BODY_BYTES", str(1 * 1024 * 1024)))
_DB_KEY: str = os.environ.get("AXION_DB_KEY", "")

app = FastAPI(title="Axion - Central Server")

_ws_clients: list = []
_start_time: float = time.time()
_in_flight: int = 0


def _setup_logging() -> logging.Logger:
    handler = logging.StreamHandler()
    try:
        from pythonjsonlogger import jsonlogger
        handler.setFormatter(
            jsonlogger.JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")
        )
    except ImportError:
        pass
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not root.handlers:
        root.addHandler(handler)
    return logging.getLogger(__name__)


log = _setup_logging()


# ---------- secrets ----------

def _load_api_key() -> Optional[str]:
    """Load AXION_API_KEY from env var or file (Docker secrets / Vault agent).

    Priority:
      1. AXION_API_KEY env var (direct value)
      2. AXION_API_KEY_FILE env var (path to a file containing the key)
    """
    key = os.environ.get("AXION_API_KEY")
    if key:
        return key
    key_file = os.environ.get("AXION_API_KEY_FILE")
    if key_file:
        try:
            return pathlib.Path(key_file).read_text().strip() or None
        except OSError as exc:
            log.error("Cannot read AXION_API_KEY_FILE %s: %s", key_file, exc)
    return None


_API_KEY: Optional[str] = _load_api_key()

# SIEM forwarder — built from AXION_SIEM_* env vars at startup.
_siem: _siem_mod.SIEMForwarder = _siem_mod.noop()

try:
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator().instrument(app).expose(app, include_in_schema=False)
except ImportError:
    pass


class _BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and int(cl) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "Request body too large."}, status_code=413)
        return await call_next(request)


class _RequestTrackingMiddleware(BaseHTTPMiddleware):
    """Track in-flight request count so shutdown can drain gracefully."""
    async def dispatch(self, request: Request, call_next):
        global _in_flight
        _in_flight += 1
        try:
            return await call_next(request)
        finally:
            _in_flight -= 1


app.add_middleware(_BodySizeLimitMiddleware)
app.add_middleware(_RequestTrackingMiddleware)


# ---------- auth helpers ----------
#
# Role hierarchy (least → most privileged):
#   analyst     — read-only: GET alerts, incidents, stats.
#   operator    — analyst + ack alerts/incidents + submit alerts via API key.
#   admin       — operator + user management + audit log + key rotation.
#   __machine__ — machine token (API key); may submit + ack. Cannot manage users.

def _require_auth(
    authorization: Optional[str] = Header(default=None),
    x_axion_key: Optional[str] = Header(default=None),
) -> str:
    """Accept either a valid Bearer JWT (dashboard) or X-Axion-Key (agents/CLI)."""
    if _API_KEY is None:
        raise HTTPException(status_code=503, detail="AXION_API_KEY not configured on server.")

    if x_axion_key and secrets.compare_digest(x_axion_key, _API_KEY):
        return "__machine__"

    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        username = decode_token(token, _API_KEY)
        if username:
            return username

    raise HTTPException(status_code=401, detail="Authentication required.")


def _require_human(actor: str = Depends(_require_auth)) -> str:
    """Require a human (JWT) session; rejects machine tokens."""
    if actor == "__machine__":
        raise HTTPException(status_code=403, detail="Human session required.")
    return actor


def _require_operator(actor: str = Depends(_require_auth)) -> str:
    """Require operator or admin role; machine tokens count as operator."""
    if actor == "__machine__":
        return actor
    conn = _conn()
    row = conn.execute("SELECT role FROM users WHERE username = ?", (actor,)).fetchone()
    conn.close()
    if not row or row["role"] not in ("admin", "operator"):
        raise HTTPException(status_code=403, detail="Operator role required.")
    return actor


def _require_admin(actor: str = Depends(_require_auth)) -> str:
    if actor == "__machine__":
        raise HTTPException(status_code=403, detail="Machine tokens cannot manage users.")
    conn = _conn()
    row = conn.execute("SELECT role FROM users WHERE username = ?", (actor,)).fetchone()
    conn.close()
    if not row or row["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required.")
    return actor


# ---------- DB ----------

def _apply_db_key(conn) -> None:
    """Apply SQLCipher key immediately after connecting."""
    if _SQLCIPHER and _DB_KEY:
        key_hex = _DB_KEY.encode().hex()
        conn.execute(f"PRAGMA key=\"x'{key_hex}'\"")
        conn.execute("PRAGMA cipher_page_size = 4096")
        conn.execute("PRAGMA kdf_iter = 64000")
        conn.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512")


def _conn():
    c = _db_module.connect(DB_PATH)
    c.row_factory = _db_module.Row
    _apply_db_key(c)
    return c


def _audit_hmac(ts: float, actor: str, action: str, target: Optional[str], detail: Optional[str]) -> Optional[str]:
    """Compute HMAC-SHA256 over the audit row fields for tamper detection.

    ts is formatted as %.6f (6 decimal places) to match the Go server's fmt.Sprintf("%f", ts),
    ensuring cross-server VerifyAudit produces consistent results.
    """
    if _API_KEY is None:
        return None
    key = hashlib.sha256(("axion-audit-v1:" + _API_KEY).encode()).digest()
    msg = f"{ts:.6f}|{actor}|{action}|{target or ''}|{detail or ''}".encode()
    return _hmac_mod.new(key, msg, digestmod=hashlib.sha256).hexdigest()


def _audit(conn, actor: str, action: str, target: Optional[str] = None, detail: Optional[str] = None):
    ts = time.time()
    row_hmac = _audit_hmac(ts, actor, action, target, detail)
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, target, detail, row_hmac) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, actor, action, target, detail, row_hmac),
    )
    # Non-blocking SIEM forward.
    _siem.send_audit({
        "ts": ts, "actor": actor, "action": action,
        "target": target, "detail": detail,
        "event_provider": "axion-server", "event_code": action,
    })


def init_db():
    conn = _conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL, detector TEXT, severity TEXT, title TEXT,
            details TEXT, node_id TEXT, location TEXT,
            acknowledged INTEGER DEFAULT 0
        )
    """)
    existing = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    for col in ["node_id TEXT", "location TEXT", "acknowledged INTEGER DEFAULT 0",
                "acknowledged_by TEXT", "acknowledged_at REAL", "acknowledged_note TEXT",
                "incident_id INTEGER"]:
        if col.split()[0] not in existing:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col}")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts     ON alerts(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts_sev ON alerts(ts, severity)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'operator',
            created_at REAL,
            last_login REAL,
            totp_secret TEXT,
            failed_login_count INTEGER DEFAULT 0,
            locked_until REAL
        )
    """)
    user_cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    for col in ["totp_secret TEXT", "failed_login_count INTEGER DEFAULT 0", "locked_until REAL"]:
        if col.split()[0] not in user_cols:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col}")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT,
            row_hmac TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")

    audit_cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    if "row_hmac" not in audit_cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN row_hmac TEXT")

    # DB-level immutability: prevent DELETE or UPDATE on audit rows.
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
        BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log rows are immutable');
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log rows are immutable');
        END
    """)

    conn.commit()
    _cor.ensure_schema(conn)
    _seed_admin(conn)
    conn.close()


def _seed_admin(conn):
    env_pw = os.environ.get("AXION_ADMIN_PASSWORD")
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    if count == 0:
        password = env_pw or secrets.token_urlsafe(16)
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            ("admin", hash_password(password), "admin", time.time()),
        )
        conn.commit()
        if not env_pw:
            print(f"\n{'='*56}")
            print(f"  AXION first-run admin account created")
            print(f"  Username : admin")
            print(f"  Password : {password}")
            print(f"  (Set AXION_ADMIN_PASSWORD to choose your own)")
            print(f"{'='*56}\n")
        else:
            print(f"\n  AXION admin account created (password from AXION_ADMIN_PASSWORD)\n")
    elif env_pw:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = 'admin'",
            (hash_password(env_pw),),
        )
        conn.commit()
        print(f"\n  AXION admin password updated from AXION_ADMIN_PASSWORD\n")


def _alert_row(r) -> dict:
    d = dict(r)
    d["details"] = json.loads(d.get("details") or "{}")
    d["acknowledged"] = bool(d.get("acknowledged"))
    return d


def _incident_row(r) -> dict:
    d = dict(r)
    d["acknowledged"] = bool(d.get("acknowledged"))
    d["detectors"] = [s.strip() for s in (d.get("detectors") or "").split(",") if s.strip()]
    return d


# ---------- lifecycle ----------

def _start_key_watcher() -> None:
    """Watch AXION_API_KEY_FILE for modifications and hot-reload the key in-memory.

    Polls every 5 seconds. On mtime change: reads the new key, updates _API_KEY,
    and writes a key_reloaded audit event. Enables zero-downtime key rotation
    without restarting the server (Vault agent sidecar pattern).
    """
    key_file = os.environ.get("AXION_API_KEY_FILE")
    if not key_file:
        return

    def _watcher() -> None:
        global _API_KEY
        last_mtime: Optional[float] = None
        while True:
            time.sleep(5)
            try:
                mtime = os.path.getmtime(key_file)
                if last_mtime is not None and mtime != last_mtime:
                    new_key = pathlib.Path(key_file).read_text().strip() or None
                    if new_key and new_key != _API_KEY:
                        _API_KEY = new_key
                        conn = _conn()
                        _audit(conn, "__system__", "key_reloaded", None,
                               f"API key hot-reloaded from {key_file}")
                        conn.commit()
                        conn.close()
                        log.info("API key hot-reloaded from %s", key_file)
                last_mtime = mtime
            except OSError:
                pass

    t = threading.Thread(target=_watcher, name="AxionKeyWatcher", daemon=True)
    t.start()
    log.info("Key file watcher started for %s", key_file)


@app.on_event("startup")
def startup():
    global _siem
    init_db()
    _siem = _siem_mod.from_env()
    _start_key_watcher()
    if _API_KEY is None:
        log.warning("AXION_API_KEY not set — all endpoints will return 503.")
    else:
        log.info("API key authentication enabled.")
    if _SQLCIPHER and _DB_KEY:
        log.info("SQLCipher DB encryption enabled.")
    elif _SQLCIPHER:
        log.warning("sqlcipher3 installed but AXION_DB_KEY not set — DB is unencrypted.")
    if not _PYOTP:
        log.warning("pyotp not installed — MFA (IA-2(1)) is unavailable.")


@app.on_event("shutdown")
async def shutdown():
    # Drain in-flight HTTP requests (up to 10 s).
    deadline = time.time() + 10.0
    while _in_flight > 0 and time.time() < deadline:
        await asyncio.sleep(0.1)
    if _in_flight > 0:
        log.warning("shutdown: %d request(s) still in flight after drain window", _in_flight)

    for ws in list(_ws_clients):
        try:
            await ws.close(code=1001)
        except Exception:
            pass
    _ws_clients.clear()
    _siem.stop(timeout=3.0)


# ---------- WebSocket broadcast ----------

async def _broadcast(msg: dict):
    dead = []
    for ws in list(_ws_clients):  # snapshot — prevents RuntimeError if a disconnect fires mid-iteration
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


# ---------- Pydantic schemas ----------

SEVERITY = Literal["low", "medium", "high", "critical"]


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)
    api_key: str = Field(..., min_length=1)
    otp: Optional[str] = Field(None, min_length=6, max_length=8, description="TOTP code (required when MFA is enabled for the account)")


class AlertPayload(BaseModel):
    ts: Optional[float] = None
    detector: str = Field(..., min_length=1, max_length=64)
    severity: SEVERITY
    title: str = Field(..., min_length=1, max_length=256)
    details: Dict[str, Any] = {}
    node_id: Optional[str] = Field(None, max_length=64)
    location: Optional[str] = Field(None, max_length=128)


class AckBody(BaseModel):
    by: Optional[str] = Field(None, max_length=128)
    note: Optional[str] = Field(None, max_length=512)


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    password: str = Field(..., min_length=8, max_length=256)
    role: Literal["admin", "operator", "analyst"] = "operator"


class RotateKeyRequest(BaseModel):
    new_key: str = Field(..., min_length=16, max_length=512,
                         description="New API key — must be at least 16 characters.")


# ---------- health / readiness ----------

@app.get("/api/health")
def health():
    """Liveness probe — always responds if the process is alive."""
    return {"status": "ok", "uptime_seconds": time.time() - _start_time}


@app.get("/api/ready")
def ready():
    """Readiness probe — verifies DB connectivity before accepting traffic."""
    try:
        conn = _conn()
        conn.execute("SELECT 1").fetchone()
        conn.close()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"DB not ready: {exc}")
    return {"status": "ready"}


# ---------- auth endpoints ----------

_MAX_LOGIN_FAILURES = 5
_LOCKOUT_SECONDS = 1800  # 30 minutes


@app.post("/api/login")
def login(req: LoginRequest):
    if _API_KEY is None:
        raise HTTPException(status_code=503, detail="AXION_API_KEY not configured.")
    if not secrets.compare_digest(req.api_key, _API_KEY):
        conn = _conn()
        _audit(conn, req.username, "login_failed", None, "invalid api_key")
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid API key.")
    conn = _conn()
    row = conn.execute(
        "SELECT password_hash, totp_secret, failed_login_count, locked_until FROM users WHERE username = ?",
        (req.username,),
    ).fetchone()

    # Account lockout check (AC-7).
    if row:
        locked_until = row["locked_until"]
        if locked_until and time.time() < locked_until:
            remaining = int(locked_until - time.time())
            _audit(conn, req.username, "login_blocked", None, f"account locked; {remaining}s remaining")
            conn.commit()
            conn.close()
            raise HTTPException(status_code=403,
                                detail=f"Account locked after repeated failures. Try again in {remaining}s.")

    if not row or not verify_password(row["password_hash"], req.password):
        if row:
            new_count = (row["failed_login_count"] or 0) + 1
            locked_until_val = (time.time() + _LOCKOUT_SECONDS) if new_count >= _MAX_LOGIN_FAILURES else None
            conn.execute(
                "UPDATE users SET failed_login_count = ?, locked_until = ? WHERE username = ?",
                (new_count, locked_until_val, req.username),
            )
        _audit(conn, req.username, "login_failed", None, "invalid credentials")
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    # TOTP validation (IA-2(1)): required when account has MFA enrolled.
    if row["totp_secret"]:
        if not _PYOTP:
            conn.close()
            raise HTTPException(status_code=503, detail="MFA required but pyotp is not installed.")
        if not req.otp:
            conn.close()
            raise HTTPException(status_code=401, detail="MFA code required.")
        totp = _pyotp.TOTP(row["totp_secret"])
        if not totp.verify(req.otp, valid_window=1):
            new_count = (row["failed_login_count"] or 0) + 1
            locked_until_val = (time.time() + _LOCKOUT_SECONDS) if new_count >= _MAX_LOGIN_FAILURES else None
            conn.execute(
                "UPDATE users SET failed_login_count = ?, locked_until = ? WHERE username = ?",
                (new_count, locked_until_val, req.username),
            )
            _audit(conn, req.username, "login_failed", None, "invalid mfa code")
            conn.commit()
            conn.close()
            raise HTTPException(status_code=401, detail="Invalid MFA code.")

    conn.execute(
        "UPDATE users SET last_login = ?, failed_login_count = 0, locked_until = NULL WHERE username = ?",
        (time.time(), req.username),
    )
    _audit(conn, req.username, "login_success")
    conn.commit()
    conn.close()
    token = create_token(req.username, _API_KEY)
    return {"token": token, "username": req.username, "expires_in": 8 * 3600}


# ---------- key rotation (admin only) ----------

@app.post("/api/rotate-key")
def rotate_key(req: RotateKeyRequest, actor: str = Depends(_require_admin)):
    """Rotate the AXION_API_KEY in-memory.

    All existing JWT sessions are immediately invalidated.  Update
    AXION_API_KEY in your env file and restart for persistence.

    Warning: audit log HMAC verification will fail for rows written before
    the rotation because the HMAC key is derived from the API key.  Archive
    the audit log before rotating if you need to verify old entries.
    """
    global _API_KEY
    conn = _conn()
    _audit(conn, actor, "key_rotated", None,
           "API key rotated — all existing JWT sessions invalidated")
    conn.commit()
    conn.close()
    _API_KEY = req.new_key
    log.warning("API key rotated by %s", actor)
    return {
        "status": "rotated",
        "warning": (
            "All existing sessions are now invalid. "
            "Update AXION_API_KEY env var and restart for persistence."
        ),
    }


# ---------- user management (admin only) ----------

@app.post("/api/users/{username}/totp")
def enable_totp(username: str, actor: str = Depends(_require_admin)):
    """Generate and store a TOTP secret for a user account (IA-2(1) MFA enrolment).

    Returns the base32 secret and a provisioning URI that can be rendered as a
    QR code for any TOTP authenticator app (Google Authenticator, Aegis, etc.).
    The secret is stored immediately; the next login for this user will require
    an OTP code.
    """
    if not _PYOTP:
        raise HTTPException(status_code=503, detail="pyotp is not installed.")
    secret = _pyotp.random_base32()
    conn = _conn()
    row = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")
    conn.execute("UPDATE users SET totp_secret = ? WHERE username = ?", (secret, username))
    _audit(conn, actor, "totp_enabled", username)
    conn.commit()
    conn.close()
    uri = _pyotp.TOTP(secret).provisioning_uri(username, issuer_name="Axion")
    return {"username": username, "totp_secret": secret, "provisioning_uri": uri}


@app.delete("/api/users/{username}/totp")
def disable_totp(username: str, actor: str = Depends(_require_admin)):
    """Remove TOTP MFA from a user account."""
    conn = _conn()
    row = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")
    conn.execute("UPDATE users SET totp_secret = NULL WHERE username = ?", (username,))
    _audit(conn, actor, "totp_disabled", username)
    conn.commit()
    conn.close()
    return {"status": "mfa_disabled", "username": username}


@app.post("/api/users/{username}/unlock")
def unlock_user(username: str, actor: str = Depends(_require_admin)):
    """Clear account lockout — resets failed_login_count and locked_until (AC-7)."""
    conn = _conn()
    row = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")
    conn.execute(
        "UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE username = ?",
        (username,),
    )
    _audit(conn, actor, "account_unlocked", username)
    conn.commit()
    conn.close()
    return {"status": "unlocked", "username": username}


@app.get("/api/users", dependencies=[Depends(_require_admin)])
def list_users():
    conn = _conn()
    rows = conn.execute(
        "SELECT id, username, role, created_at, last_login FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/users")
def create_user(req: CreateUserRequest, actor: str = Depends(_require_admin)):
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (req.username, hash_password(req.password), req.role, time.time()),
        )
        _audit(conn, actor, "user_created", req.username, req.role)
        conn.commit()
    except Exception:
        raise HTTPException(status_code=409, detail="Username already exists.")
    finally:
        conn.close()
    return {"status": "created", "username": req.username}


@app.delete("/api/users/{username}")
def delete_user(username: str, actor: str = Depends(_require_admin)):
    if username == actor:
        raise HTTPException(status_code=400, detail="Cannot delete your own account.")
    conn = _conn()
    cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")
    _audit(conn, actor, "user_deleted", username)
    conn.commit()
    conn.close()
    return {"status": "deleted"}


# ---------- audit log (admin only) ----------

@app.get("/api/audit", dependencies=[Depends(_require_admin)])
def list_audit(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    actor: Optional[str] = None,
    action: Optional[str] = None,
):
    clauses, params = [], []
    if actor:  clauses.append("actor = ?");  params.append(actor)
    if action: clauses.append("action = ?"); params.append(action)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = _conn()
    rows = conn.execute(
        f"SELECT id, ts, actor, action, target, detail FROM audit_log {where} "
        f"ORDER BY ts DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/audit/verify", dependencies=[Depends(_require_admin)])
def verify_audit_integrity():
    """Re-compute HMAC for every audit row and report any that don't match."""
    if _API_KEY is None:
        raise HTTPException(status_code=503, detail="AXION_API_KEY not configured.")
    key = hashlib.sha256(("axion-audit-v1:" + _API_KEY).encode()).digest()
    conn = _conn()
    rows = conn.execute(
        "SELECT id, ts, actor, action, target, detail, row_hmac FROM audit_log ORDER BY id"
    ).fetchall()
    conn.close()
    tampered: list = []
    missing: list = []
    for r in rows:
        if r["row_hmac"] is None:
            missing.append(r["id"])
            continue
        msg = f"{r['ts']:.6f}|{r['actor']}|{r['action']}|{r['target'] or ''}|{r['detail'] or ''}".encode()
        expected = _hmac_mod.new(key, msg, digestmod=hashlib.sha256).hexdigest()
        if not secrets.compare_digest(r["row_hmac"], expected):
            tampered.append(r["id"])
    ok_count = len(rows) - len(tampered) - len(missing)
    return {
        "total": len(rows),
        "ok": ok_count,
        "tampered_ids": tampered,
        "missing_hmac_ids": missing,
        "integrity": "PASS" if not tampered else "FAIL",
    }


# ---------- alerts ----------

@app.post("/api/alerts", dependencies=[Depends(_require_operator)])
async def ingest_alert(payload: AlertPayload):
    ts = payload.ts or time.time()
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO alerts (ts, detector, severity, title, details, node_id, location) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, payload.detector, payload.severity, payload.title,
         json.dumps(payload.details), payload.node_id, payload.location),
    )
    conn.commit()
    alert_id = cur.lastrowid
    inc_id = _cor.correlate(
        conn, alert_id=alert_id, ts=ts, detector=payload.detector,
        severity=payload.severity, details=payload.details,
    )
    _audit(conn, "__system__", "incident_correlated", str(inc_id),
           f"alert_id={alert_id} detector={payload.detector} severity={payload.severity}")
    conn.commit()
    conn.close()

    # Forward to SIEM (non-blocking).
    _siem.send_alert({
        "ts": ts,
        "alert_id": alert_id,
        "incident_id": inc_id,
        "detector": payload.detector,
        "severity": payload.severity,
        "title": payload.title,
        "details": payload.details,
        "node_id": payload.node_id,
        "location": payload.location,
        "event_provider": "axion-server",
        "event_code": "ALERT_INGESTED",
    })

    await _broadcast({"type": "alert", "detector": payload.detector, "incident_id": inc_id})
    return {"status": "stored", "alert_id": alert_id, "incident_id": inc_id}


@app.get("/api/alerts", dependencies=[Depends(_require_auth)])
def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    detector: Optional[str] = None,
    node_id: Optional[str] = None,
    q: Optional[str] = Query(None, max_length=200),
    hide_acked: bool = False,
    incident_id: Optional[int] = None,
):
    clauses, params = [], []
    if severity:   clauses.append("severity = ?");  params.append(severity)
    if detector:   clauses.append("detector = ?");  params.append(detector)
    if node_id:    clauses.append("node_id = ?");   params.append(node_id)
    if q:
        clauses.append("(title LIKE ? OR details LIKE ? OR node_id LIKE ? OR detector LIKE ? OR location LIKE ?)")
        params += [f"%{q}%"] * 5
    if hide_acked: clauses.append("acknowledged = 0")
    if incident_id is not None:
        clauses.append("incident_id = ?"); params.append(incident_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = _conn()
    rows = conn.execute(
        f"SELECT id, ts, detector, severity, title, details, node_id, location, "
        f"acknowledged, acknowledged_by, acknowledged_at, acknowledged_note, incident_id "
        f"FROM alerts {where} ORDER BY ts DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    conn.close()
    return [_alert_row(r) for r in rows]


@app.post("/api/alerts/{alert_id}/ack")
async def ack_alert(alert_id: int, body: AckBody = AckBody(), actor: str = Depends(_require_operator)):
    now = time.time()
    conn = _conn()
    conn.execute(
        "UPDATE alerts SET acknowledged=1, acknowledged_by=?, acknowledged_at=?, acknowledged_note=? WHERE id=?",
        (body.by or actor, now, body.note, alert_id),
    )
    _audit(conn, actor, "ack_alert", str(alert_id), body.note)
    conn.commit()
    conn.close()
    return {"status": "acknowledged"}


@app.get("/api/stats", dependencies=[Depends(_require_auth)])
def stats(window_minutes: int = Query(60, ge=1)):
    since = time.time() - window_minutes * 60
    conn = _conn()
    rows = conn.execute(
        "SELECT ts, severity, detector, node_id FROM alerts WHERE ts >= ? ORDER BY ts", (since,)
    ).fetchall()
    open_incidents = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE acknowledged = 0"
    ).fetchone()[0]
    conn.close()

    by_severity: dict = {}
    by_detector: dict = {}
    by_node: dict = {}
    timeline: dict = {}
    for r in rows:
        ts, sev, det, node = r["ts"], r["severity"], r["detector"], r["node_id"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_detector[det] = by_detector.get(det, 0) + 1
        by_node[node]    = by_node.get(node, 0) + 1
        bucket = int(ts / 60) * 60
        timeline[bucket] = timeline.get(bucket, 0) + 1

    return {
        "total": len(rows),
        "open_incidents": open_incidents,
        "by_severity": by_severity,
        "by_detector": sorted(
            [{"detector": k, "count": v} for k, v in by_detector.items()],
            key=lambda x: -x["count"],
        ),
        "by_node": sorted(
            [{"node_id": k, "count": v} for k, v in by_node.items()],
            key=lambda x: -x["count"],
        ),
        "timeline": [{"ts": k, "count": v} for k, v in sorted(timeline.items())],
    }


# ---------- incidents ----------

@app.get("/api/incidents", dependencies=[Depends(_require_auth)])
def list_incidents(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    hide_acked: bool = True,
):
    clauses, params = [], []
    if hide_acked:
        clauses.append("acknowledged = 0")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = _conn()
    rows = conn.execute(
        f"SELECT id, created_at, updated_at, severity, title, alert_count, detectors, "
        f"acknowledged, acknowledged_by, acknowledged_at, acknowledged_note "
        f"FROM incidents {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    result = []
    for r in rows:
        inc = _incident_row(r)
        inc["entities"] = [
            e[0] for e in conn.execute(
                "SELECT entity FROM incident_entities WHERE incident_id = ?", (inc["id"],)
            ).fetchall()
        ]
        result.append(inc)
    conn.close()
    return result


@app.get("/api/incidents/{inc_id}", dependencies=[Depends(_require_auth)])
def get_incident(inc_id: int):
    conn = _conn()
    row = conn.execute(
        "SELECT id, created_at, updated_at, severity, title, alert_count, detectors, "
        "acknowledged, acknowledged_by, acknowledged_at, acknowledged_note "
        "FROM incidents WHERE id = ?", (inc_id,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="incident not found")
    inc = _incident_row(row)
    inc["entities"] = [
        e[0] for e in conn.execute(
            "SELECT entity FROM incident_entities WHERE incident_id = ?", (inc_id,)
        ).fetchall()
    ]
    inc["alerts"] = [
        _alert_row(r) for r in conn.execute(
            "SELECT id, ts, detector, severity, title, details, node_id, location, "
            "acknowledged, acknowledged_by, acknowledged_at, acknowledged_note, incident_id "
            "FROM alerts WHERE incident_id = ? ORDER BY ts ASC", (inc_id,)
        ).fetchall()
    ]
    conn.close()
    return inc


@app.post("/api/incidents/{inc_id}/ack")
async def ack_incident(inc_id: int, body: AckBody = AckBody(), actor: str = Depends(_require_operator)):
    now = time.time()
    conn = _conn()
    conn.execute(
        "UPDATE incidents SET acknowledged=1, acknowledged_by=?, acknowledged_at=?, acknowledged_note=? WHERE id=?",
        (body.by or actor, now, body.note, inc_id),
    )
    conn.execute(
        "UPDATE alerts SET acknowledged=1, acknowledged_by=?, acknowledged_at=?, acknowledged_note=? "
        "WHERE incident_id=? AND acknowledged=0",
        (body.by or actor, now, body.note, inc_id),
    )
    _audit(conn, actor, "ack_incident", str(inc_id), body.note)
    conn.commit()
    conn.close()
    return {"status": "acknowledged"}


# ---------- static ----------

static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(static_dir, "index.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.websocket("/api/ws")
async def ws_endpoint(websocket: WebSocket, token: Optional[str] = Query(default=None)):
    await websocket.accept()
    if _API_KEY is None or not token:
        await websocket.close(code=1008)
        return
    username = decode_token(token, _API_KEY)
    if not username:
        await websocket.close(code=1008)
        return
    conn = _conn()
    _audit(conn, username, "ws_connect")
    conn.commit()
    conn.close()
    _ws_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)
        conn = _conn()
        _audit(conn, username, "ws_disconnect")
        conn.commit()
        conn.close()


def main():
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--ssl-certfile", default=None)
    ap.add_argument("--ssl-keyfile", default=None)
    ap.add_argument("--ssl-client-ca", default=None,
                    help="CA cert for mTLS client verification.")
    args = ap.parse_args()

    kwargs: Dict[str, Any] = dict(
        app="tacnet_sec.server.api:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="info",
    )
    if args.ssl_certfile and args.ssl_keyfile:
        kwargs["ssl_certfile"] = args.ssl_certfile
        kwargs["ssl_keyfile"] = args.ssl_keyfile
    if args.ssl_client_ca:
        kwargs["ssl_ca_certs"] = args.ssl_client_ca

    uvicorn.run(**kwargs)


if __name__ == "__main__":
    main()
