from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


@dataclass
class AuditRecord:
    timestamp: str
    category: str
    action: str
    source: str
    rule: str
    user_role: str
    outcome: str
    safe_reference: str = ""
    entity_fingerprint_hmac: str = ""
    row_hmac: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "timestamp": self.timestamp,
            "category": self.category,
            "action": self.action,
            "source": self.source,
            "rule": self.rule,
            "user_role": self.user_role,
            "outcome": self.outcome,
            "safe_reference": self.safe_reference,
            "entity_fingerprint_hmac": self.entity_fingerprint_hmac,
            "row_hmac": self.row_hmac,
        }


class AuditLogger:
    def __init__(self, key_path: Path | None = None, database_path: Path | None = None):
        self.records: List[AuditRecord] = []
        self.key_path = key_path or Path(__file__).resolve().parents[1] / "config" / ".hmac_master_key"
        configured_database = os.environ.get("INTENTLOCK_AUDIT_DB", "data/audit_events.db")
        self.database_path = database_path or Path(configured_database)
        if not self.database_path.is_absolute():
            self.database_path = Path(__file__).resolve().parents[1] / self.database_path
        self._lock = threading.RLock()
        self._key = self._load_or_create_key()
        self._initialize_database()
        if not self.verify_integrity():
            raise RuntimeError("Audit ledger integrity verification failed")

    def _load_or_create_key(self) -> bytes:
        configured_key = os.environ.get("INTENTLOCK_HMAC_KEY")
        if configured_key:
            return configured_key.encode("utf-8")

        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(self.key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return self.key_path.read_bytes()
        key = secrets.token_bytes(32)
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(key)
            key_file.flush()
            os.fsync(key_file.fileno())
        try:
            self.key_path.chmod(0o600)
        except OSError:
            pass
        return key

    def _sign(self, value: bytes) -> str:
        return hmac.new(self._key, value, hashlib.sha256).hexdigest()

    def _initialize_database(self) -> None:
        self.database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.database_path.parent.chmod(0o700)
        except OSError:
            pass
        with sqlite3.connect(self.database_path) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS audit_events (
                    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    category TEXT NOT NULL,
                    action TEXT NOT NULL,
                    source TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    user_role TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    safe_reference TEXT NOT NULL,
                    entity_fingerprint_hmac TEXT NOT NULL,
                    row_hmac TEXT NOT NULL
                )"""
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_events(category)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_role ON audit_events(user_role)")
            rows = connection.execute(
                "SELECT timestamp, category, action, source, rule, user_role, outcome, "
                "safe_reference, entity_fingerprint_hmac, row_hmac "
                "FROM audit_events ORDER BY event_seq"
            ).fetchall()
        try:
            self.database_path.chmod(0o600)
        except OSError:
            pass
        self.records = [AuditRecord(*row) for row in rows]

    def log(
        self,
        *,
        category: str,
        action: str,
        source: str,
        rule: str,
        user_role: str,
        outcome: str,
        safe_reference: str = "",
        entity: str = "",
    ) -> AuditRecord:
        entity_fingerprint = self._sign(entity.encode("utf-8")) if entity else ""
        with self._lock:
            record = AuditRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                category=category,
                action=action,
                source=source,
                rule=rule,
                user_role=user_role,
                outcome=outcome,
                safe_reference=safe_reference or f"ref:{len(self.records) + 1:04d}",
                entity_fingerprint_hmac=entity_fingerprint,
            )
            with sqlite3.connect(self.database_path, isolation_level=None, timeout=15) as connection:
                connection.execute("BEGIN IMMEDIATE")
                previous_row = connection.execute(
                    "SELECT row_hmac FROM audit_events ORDER BY event_seq DESC LIMIT 1"
                ).fetchone()
                previous_signature = previous_row[0] if previous_row else ""
                payload = json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
                record.row_hmac = self._sign(previous_signature.encode("ascii") + payload)
                connection.execute(
                    "INSERT INTO audit_events (timestamp, category, action, source, rule, user_role, outcome, "
                    "safe_reference, entity_fingerprint_hmac, row_hmac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        record.timestamp, record.category, record.action, record.source, record.rule,
                        record.user_role, record.outcome, record.safe_reference,
                        record.entity_fingerprint_hmac, record.row_hmac,
                    ),
                )
                connection.commit()
                rows = connection.execute(
                    "SELECT timestamp, category, action, source, rule, user_role, outcome, "
                    "safe_reference, entity_fingerprint_hmac, row_hmac "
                    "FROM audit_events ORDER BY event_seq"
                ).fetchall()
            self.records = [AuditRecord(*row) for row in rows]
            return record

    def clear(self) -> None:
        with self._lock, sqlite3.connect(self.database_path) as connection:
            connection.execute("DELETE FROM audit_events")
            self.records.clear()

    def snapshot(self) -> List[Dict[str, str]]:
        with self._lock:
            return [record.to_dict() for record in self.records]

    def verify_integrity(self) -> bool:
        with self._lock, sqlite3.connect(self.database_path) as connection:
            rows = connection.execute(
                "SELECT timestamp, category, action, source, rule, user_role, outcome, "
                "safe_reference, entity_fingerprint_hmac, row_hmac "
                "FROM audit_events ORDER BY event_seq"
            ).fetchall()
            self.records = [AuditRecord(*row) for row in rows]
        previous_signature = ""
        for record in self.records:
            payload = record.to_dict()
            payload["row_hmac"] = ""
            serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            expected_signature = self._sign(previous_signature.encode("ascii") + serialized)
            if not hmac.compare_digest(record.row_hmac, expected_signature):
                return False
            previous_signature = record.row_hmac
        return True
