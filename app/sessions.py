from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict


@dataclass
class SessionBuffer:
    turns: Deque[str] = field(default_factory=deque)
    updated_at: float = 0.0


class SessionManager:
    def __init__(self, *, max_turns: int = 5, max_chars: int = 4096, ttl_seconds: int = 1800):
        self.max_turns = max_turns
        self.max_chars = max_chars
        self.ttl_seconds = ttl_seconds
        self._sessions: Dict[tuple[str, str], SessionBuffer] = {}
        self._lock = threading.RLock()

    def append_and_get_context(
        self,
        user_id: str,
        session_id: str | None,
        prompt: str,
        *,
        now: float | None = None,
    ) -> str:
        if not session_id:
            return prompt
        current = time.monotonic() if now is None else now
        key = (user_id, session_id)
        with self._lock:
            expired = [
                session_key
                for session_key, buffer in self._sessions.items()
                if current - buffer.updated_at >= self.ttl_seconds
            ]
            for session_key in expired:
                del self._sessions[session_key]

            buffer = self._sessions.setdefault(key, SessionBuffer())
            buffer.turns.append(prompt)
            buffer.updated_at = current
            while buffer.turns and (
                len(buffer.turns) > self.max_turns
                or sum(len(turn) for turn in buffer.turns) > self.max_chars
            ):
                buffer.turns.popleft()
            return "\n".join(buffer.turns)

    def clear(self, user_id: str, session_id: str) -> None:
        with self._lock:
            self._sessions.pop((user_id, session_id), None)