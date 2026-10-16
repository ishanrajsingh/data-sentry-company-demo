from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

import bcrypt
from fastapi import HTTPException, Request


COOKIE_NAME = "northstar_session"
SESSION_TTL_SECONDS = 60 * 60 * 8


def _secret() -> bytes:
    return os.getenv("SESSION_SECRET", "local-demo-only-change-this-secret").encode("utf-8")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def create_session(user: dict[str, Any]) -> str:
    payload = {
        "sub": user["user_id"],
        "email": user["email"],
        "exp": int(time.time()) + SESSION_TTL_SECONDS,
    }
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _b64url(hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{signature}"


def decode_session(token: str) -> dict[str, Any] | None:
    try:
        body, signature = token.split(".", 1)
        expected = _b64url(hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        padding = "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(body + padding))
        if not isinstance(payload, dict) or int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def authenticate_password(user: dict[str, Any] | None, password: str) -> bool:
    if not user or not user.get("active", True):
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("ascii"))
    except (ValueError, TypeError, KeyError):
        return False


def request_user(request: Request) -> dict[str, Any]:
    token = request.cookies.get(COOKIE_NAME)
    payload = decode_session(token) if token else None
    if not payload:
        raise HTTPException(status_code=401, detail="Please sign in to continue.")
    store = request.app.state.store
    user = store.find_user(str(payload.get("email", "")))
    if not user or user.get("user_id") != payload.get("sub") or not user.get("active", True):
        raise HTTPException(status_code=401, detail="Your session is no longer valid.")
    return user


def public_user(user: dict[str, Any]) -> dict[str, str]:
    return {
        "email": user["email"],
        "role": user["role"],
        "clearance": user["clearance"],
        "department": user["department"],
        "display_name": user.get("display_name", user["email"].split("@")[0]),
        "company": "Northstar Systems",
    }
