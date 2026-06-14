"""
Password hashing and JWT helpers.

Passwords: PBKDF2-HMAC-SHA256, 200 000 iterations — no external deps.
Tokens:    HS256 JWT via PyJWT, signed with a secret derived from AXION_API_KEY.
"""

from __future__ import annotations

import binascii, hashlib, os, secrets, time
from typing import Optional

import jwt

_ALGORITHM = "HS256"
_TOKEN_HOURS = 8


# ---------- password ----------

def hash_password(password: str) -> str:
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return binascii.hexlify(salt).decode() + ":" + binascii.hexlify(key).decode()


def verify_password(stored: str, candidate: str) -> bool:
    try:
        salt_hex, key_hex = stored.split(":", 1)
        salt = binascii.unhexlify(salt_hex)
        key = hashlib.pbkdf2_hmac("sha256", candidate.encode(), salt, 200_000)
        return secrets.compare_digest(binascii.hexlify(key).decode(), key_hex)
    except Exception:
        return False


# ---------- JWT ----------

def _signing_secret(api_key: str) -> bytes:
    # PBKDF2-derived bytes instead of a single-pass SHA256 hex string.
    # Breaking change vs prior sessions: existing tokens issued before this
    # change will be rejected. All tokens expire in 8h anyway.
    return hashlib.pbkdf2_hmac("sha256", api_key.encode(), b"axion-jwt-v1", 100_000)


def create_token(username: str, api_key: str) -> str:
    now = time.time()
    payload = {"sub": username, "iat": now, "exp": now + _TOKEN_HOURS * 3600}
    return jwt.encode(payload, _signing_secret(api_key), algorithm=_ALGORITHM)


def decode_token(token: str, api_key: str) -> Optional[str]:
    try:
        payload = jwt.decode(
            token, _signing_secret(api_key), algorithms=[_ALGORITHM]
        )
        return payload.get("sub")
    except Exception:
        return None
