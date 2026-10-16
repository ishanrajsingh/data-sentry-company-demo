from __future__ import annotations

import bcrypt
import hashlib
import json
import os
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.configuration import PROJECT_ROOT


MAX_PROMPT_BYTES = 32_768
_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class APIPrincipal:
    name: str
    role: str
    department: str = "General"
    clearance: str = "INTERNAL"


class SlidingWindowLimiter:
    def __init__(self, limit: int = 60, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self._requests: Dict[str, Deque[float]] = {}
        self._blocked: Dict[str, Deque[float]] = {}
        self._cooldowns: Dict[str, float] = {}
        self._lock = threading.Lock()

    def allow(self, user_id: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            if current < self._cooldowns.get(user_id, 0):
                return False
            history = self._requests.setdefault(user_id, deque())
            while history and current - history[0] >= self.window_seconds:
                history.popleft()
            if len(history) >= self.limit:
                return False
            history.append(current)
            return True

    def record_block(self, user_id: str, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        with self._lock:
            history = self._blocked.setdefault(user_id, deque())
            while history and current - history[0] >= self.window_seconds:
                history.popleft()
            history.append(current)
            if len(history) >= 3:
                cooldown_seconds = min(30 * (2 ** (len(history) - 3)), 300)
                self._cooldowns[user_id] = current + cooldown_seconds

    def record_success(self, user_id: str) -> None:
        with self._lock:
            self._blocked.pop(user_id, None)
            self._cooldowns.pop(user_id, None)


_limiter = SlidingWindowLimiter()
_seed_lock = threading.Lock()
_seeded_registries: Dict[str, str] = {}


def record_blocked_request(user_id: str) -> None:
    _limiter.record_block(user_id)


def record_successful_request(user_id: str) -> None:
    _limiter.record_success(user_id)


def _configured_principal(credentials: str) -> APIPrincipal | None:
    try:
        key_registry = json.loads(os.environ.get("INTENTLOCK_API_KEYS", "{}"))
    except json.JSONDecodeError:
        return None
    if not isinstance(key_registry, dict):
        return None
    configured_path = Path(os.environ.get("INTENTLOCK_USERS_DB", "data/users.db"))
    database_path = configured_path if configured_path.is_absolute() else PROJECT_ROOT / configured_path
    database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        database_path.parent.chmod(0o700)
    except OSError:
        pass
    registry_fingerprint = hashlib.sha256(
        json.dumps(key_registry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with _seed_lock:
        if _seeded_registries.get(str(database_path)) != registry_fingerprint:
            with sqlite3.connect(database_path) as connection:
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS users (
                        user_id TEXT PRIMARY KEY,
                        api_key_hash TEXT NOT NULL,
                        display_name TEXT NOT NULL,
                        role TEXT NOT NULL,
                        clearance TEXT NOT NULL,
                        department TEXT NOT NULL,
                        is_active INTEGER NOT NULL DEFAULT 1
                    )"""
                )
                connection.execute("UPDATE users SET is_active = 0")
            for api_key, attributes in key_registry.items():
                if not isinstance(api_key, str) or not isinstance(attributes, dict):
                    continue
                role = attributes.get("role")
                if role not in {"guest", "employee", "manager", "support", "hr", "executive", "security_admin"}:
                    continue
                hashed_key = bcrypt.hashpw(api_key.encode("utf-8"), bcrypt.gensalt()).decode("ascii")
                with sqlite3.connect(database_path) as connection:
                    connection.execute(
                        "INSERT INTO users (user_id, api_key_hash, display_name, role, clearance, department) "
                        "VALUES (?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(user_id) DO UPDATE SET api_key_hash=excluded.api_key_hash, "
                        "display_name=excluded.display_name, role=excluded.role, clearance=excluded.clearance, "
                        "department=excluded.department, is_active=1",
                        (
                            str(attributes.get("name", "api-user")),
                            hashed_key,
                            str(attributes.get("name", "api-user")),
                            role,
                            str(attributes.get("clearance", "INTERNAL")).upper(),
                            str(attributes.get("department", "General")),
                        ),
                    )
            _seeded_registries[str(database_path)] = registry_fingerprint

    with sqlite3.connect(database_path) as connection:
        rows = connection.execute(
            "SELECT user_id, api_key_hash, role, clearance, department "
            "FROM users WHERE is_active = 1"
        ).fetchall()
    try:
        database_path.chmod(0o600)
    except OSError:
        pass

    matched = None
    for user_id, key_hash, role, clearance, department in rows:
        try:
            key_matches = bcrypt.checkpw(credentials.encode("utf-8"), key_hash.encode("ascii"))
        except (ValueError, TypeError):
            key_matches = False
        if key_matches:
            matched = APIPrincipal(name=user_id, role=role, department=department, clearance=clearance)
    return matched


def authorize_api_request(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> APIPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Bearer"})
    principal = _configured_principal(credentials.credentials)
    if principal is None:
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Bearer"})
    if not _limiter.allow(principal.name):
        raise HTTPException(status_code=429, detail="Request limit exceeded")
    return principal


def enforce_prompt_size(prompt: str) -> None:
    if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise HTTPException(status_code=413, detail="Prompt exceeds the 32 KB limit")