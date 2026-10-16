"""Adjust heuristic risk scores using analyst feedback.

Feedback is stored in SQLite and used to tune scoped signal weights and exact
prompt corrections. It does not retrain the semantic reviewer or change hard
DLP and document-permission rules.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Database location — persists across restarts
_DB_PATH = Path(__file__).parent.parent / "data" / "adaptive_learning.db"


def _load_fingerprint_key() -> bytes:
    configured = os.environ.get("INTENTLOCK_HMAC_KEY")
    if configured:
        return configured.encode("utf-8")
    key_path = Path(__file__).resolve().parents[1] / "config" / ".hmac_master_key"
    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return key_path.read_bytes()
    key = secrets.token_bytes(32)
    with os.fdopen(descriptor, "wb") as key_file:
        key_file.write(key)
        key_file.flush()
        os.fsync(key_file.fileno())
    return key


_FINGERPRINT_KEY = _load_fingerprint_key()


@dataclass
class DecisionRecord:
    """A single recorded gateway decision with optional analyst correction."""
    prompt_hash:    str       # SHA-256 of normalised prompt (never store raw PII)
    prompt_excerpt: str       # First 80 safe chars for display
    timestamp:      float
    ti_score:       int       # 0-100 composite risk score at decision time
    risk_level:     str       # LOW/MEDIUM/HIGH/CRITICAL
    blocked:        bool      # What the system decided
    top_signal:     str       # Highest-weight signal name
    attack_cats:    str       # JSON list of attack categories
    # Feedback fields (set later)
    analyst_correct: Optional[bool] = None   # True=system was right, False=wrong
    analyst_label:   Optional[str]  = None   # "true_positive" | "false_positive" | "false_negative"
    analyst_note:    Optional[str]  = None


@dataclass
class PatternCandidate:
    """A phrase extracted from confirmed-attack prompts, candidate for DLP injection list."""
    phrase:      str
    source_hash: str    # prompt it came from
    confidence:  float  # 0-1
    confirmed:   bool = False


class FeedbackStore:
    """SQLite-backed persistent store for decision history and analyst feedback."""

    def __init__(self, db_path: Path = _DB_PATH):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._setup()

    def _setup(self):
        c = self._conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS decisions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                prompt_hash     TEXT NOT NULL,
                prompt_excerpt  TEXT,
                timestamp       REAL NOT NULL,
                ti_score        INTEGER,
                risk_level      TEXT,
                blocked         INTEGER,
                top_signal      TEXT,
                attack_cats     TEXT,
                analyst_correct INTEGER,
                analyst_label   TEXT,
                analyst_note    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_hash ON decisions(prompt_hash);
            CREATE INDEX IF NOT EXISTS idx_ts   ON decisions(timestamp);

            CREATE TABLE IF NOT EXISTS pattern_candidates (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                phrase      TEXT UNIQUE,
                source_hash TEXT,
                confidence  REAL,
                hit_count   INTEGER DEFAULT 1,
                confirmed   INTEGER DEFAULT 0,
                created_at  REAL
            );

            CREATE TABLE IF NOT EXISTS false_positive_memory (
                prompt_hash TEXT PRIMARY KEY,
                excerpt     TEXT,
                count       INTEGER DEFAULT 1,
                last_seen   REAL
            );

            CREATE TABLE IF NOT EXISTS confirmed_attack_memory (
                prompt_hash TEXT PRIMARY KEY,
                count INTEGER DEFAULT 1,
                last_seen REAL
            );

            CREATE TABLE IF NOT EXISTS learned_score_adjustments (
                signal_name TEXT PRIMARY KEY,
                adjustment  REAL DEFAULT 0.0,
                sample_count INTEGER DEFAULT 0,
                updated_at  REAL
            );
        """)
        self._conn.commit()

    def record_decision(
        self,
        prompt: str,
        ti_score: int,
        risk_level: str,
        blocked: bool,
        top_signal: str,
        attack_cats: List[str],
        scope: str = "",
    ) -> str:
        """Record a gateway decision. Returns the prompt_hash for later feedback."""
        h = _hash_prompt(prompt, scope=scope)
        # Keep only the keyed prompt fingerprint. Even a short excerpt can
        # retain names, contact details, or credential fragments.
        excerpt = "[prompt content withheld]"
        c = self._conn.cursor()
        # Defensive coercion: ensure all params are native Python types
        # (prevents sqlite3.InterfaceError if numpy/custom types are passed)
        safe_score = int(ti_score) if ti_score is not None else 0
        safe_risk = str(risk_level) if risk_level else "LOW"
        safe_blocked = bool(blocked)
        safe_top = str(top_signal) if top_signal else ""
        safe_cats = json.dumps([str(c) for c in (attack_cats or [])])
        try:
            c.execute("""
                INSERT INTO decisions
                (prompt_hash, prompt_excerpt, timestamp, ti_score, risk_level, blocked, top_signal, attack_cats)
                VALUES (?,?,?,?,?,?,?,?)
            """, (h, excerpt, time.time(), safe_score, safe_risk, int(safe_blocked),
                  safe_top, safe_cats))
            self._conn.commit()
        except Exception:
            # Non-fatal: decision logging failure should not break gateway
            try:
                self._conn.rollback()
            except Exception:
                pass
        return h

    def submit_feedback(
        self,
        prompt_hash: str,
        correct: bool,
        label: str,
        note: str = "",
    ) -> bool:
        """Analyst submits feedback on the most recent decision for a prompt_hash."""
        c = self._conn.cursor()
        c.execute("""
            UPDATE decisions
            SET analyst_correct=?, analyst_label=?, analyst_note=?
            WHERE id = (
                SELECT id FROM decisions WHERE prompt_hash=?
                ORDER BY timestamp DESC
                LIMIT 1
            )
        """, (int(correct), label, "", prompt_hash))
        self._conn.commit()
        updated = c.rowcount > 0
        if not updated:
            return False
        # Confirmations and corrections provide supervised signals. Corrections
        # carry more weight, while deterministic policy gates remain authoritative.
        self._update_score_adjustment(prompt_hash, label)
        if label == "false_negative":
            c.execute("""
                INSERT INTO confirmed_attack_memory (prompt_hash, count, last_seen)
                VALUES (?, 1, ?)
                ON CONFLICT(prompt_hash) DO UPDATE SET count=count+1, last_seen=excluded.last_seen
            """, (prompt_hash, time.time()))
            self._conn.commit()
        return True

    def _update_score_adjustment(self, prompt_hash: str, label: str):
        """Adjust future scoring for signals that caused FP or FN."""
        c = self._conn.cursor()
        row = c.execute("""
            SELECT top_signal, ti_score FROM decisions WHERE prompt_hash=?
            ORDER BY timestamp DESC LIMIT 1
        """, (prompt_hash,)).fetchone()
        if not row:
            return
        signal_name, ti_score = row[0], row[1]
        if not signal_name:
            return

        # False positive: system over-scored → negative adjustment
        # False negative: system under-scored → positive adjustment
        delta = {
            "true_positive": 0.03,
            "true_negative": -0.03,
            "false_positive": -0.08,
            "false_negative": 0.15,
        }.get(label, 0.0)
        if not delta:
            return

        c.execute("""
            INSERT INTO learned_score_adjustments (signal_name, adjustment, sample_count, updated_at)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(signal_name) DO UPDATE SET
                adjustment   = MIN(0.50, MAX(-0.30,
                                   (adjustment * sample_count + ?) / (sample_count + 1))),
                sample_count = sample_count + 1,
                updated_at   = ?
        """, (signal_name, delta, time.time(), delta, time.time()))
        self._conn.commit()

        # If false positive, add to FP memory to avoid future blocks
        if label == "false_positive":
            c.execute("""
                INSERT INTO false_positive_memory (prompt_hash, excerpt, last_seen)
                VALUES (?,?,?)
                ON CONFLICT(prompt_hash) DO UPDATE SET
                    count=count+1, last_seen=?
            """, (prompt_hash, "", time.time(), time.time()))
            self._conn.commit()

    def get_score_adjustments(self) -> Dict[str, float]:
        """Returns learned per-signal score adjustments."""
        c = self._conn.cursor()
        rows = c.execute(
            "SELECT signal_name, adjustment FROM learned_score_adjustments"
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    def is_known_false_positive(self, prompt: str, scope: str = "") -> bool:
        """Check if this prompt hash is a known false positive."""
        h = _hash_prompt(prompt, scope=scope)
        c = self._conn.cursor()
        row = c.execute(
            "SELECT count FROM false_positive_memory WHERE prompt_hash=?", (h,)
        ).fetchone()
        return row is not None and row[0] >= 2  # require 2+ confirmations

    def is_confirmed_attack(self, prompt: str, scope: str = "") -> bool:
        """Check privacy-preserving exact-prompt memory for analyst-confirmed attacks."""
        h = _hash_prompt(prompt, scope=scope)
        row = self._conn.execute(
            "SELECT 1 FROM confirmed_attack_memory WHERE prompt_hash=?", (h,)
        ).fetchone()
        return row is not None

    def update_latest_decision_outcome(
        self, prompt_hash: str, *, blocked: bool, ti_score: int, risk_level: str, top_signal: str
    ) -> bool:
        """Correct the latest recorded outcome after a later semantic gate decision."""
        cursor = self._conn.execute("""
            UPDATE decisions SET blocked=?, ti_score=?, risk_level=?, top_signal=?
            WHERE id=(SELECT id FROM decisions WHERE prompt_hash=? ORDER BY timestamp DESC, id DESC LIMIT 1)
        """, (int(blocked), int(ti_score), str(risk_level), str(top_signal), prompt_hash))
        self._conn.commit()
        return cursor.rowcount > 0

    def add_pattern_candidate(self, phrase: str, source_hash: str, confidence: float):
        """Add an extracted phrase as a candidate new injection pattern."""
        c = self._conn.cursor()
        c.execute("""
            INSERT INTO pattern_candidates (phrase, source_hash, confidence, created_at)
            VALUES (?,?,?,?)
            ON CONFLICT(phrase) DO UPDATE SET
                hit_count  = hit_count + 1,
                confidence = MAX(confidence, ?),
                created_at = ?
        """, (phrase.lower().strip(), source_hash, confidence, time.time(), confidence, time.time()))
        self._conn.commit()

    def get_high_confidence_candidates(self, min_hits: int = 3, min_conf: float = 0.75) -> List[PatternCandidate]:
        """Return pattern candidates ready for human review / auto-promotion."""
        c = self._conn.cursor()
        rows = c.execute("""
            SELECT phrase, source_hash, confidence, confirmed
            FROM pattern_candidates
            WHERE hit_count >= ? AND confidence >= ? AND confirmed = 0
            ORDER BY confidence DESC
        """, (min_hits, min_conf)).fetchall()
        return [PatternCandidate(phrase=r[0], source_hash=r[1], confidence=r[2], confirmed=bool(r[3]))
                for r in rows]

    def confirm_pattern(self, phrase: str):
        """Mark a pattern candidate as confirmed (promoted to DLP list)."""
        c = self._conn.cursor()
        c.execute("UPDATE pattern_candidates SET confirmed=1 WHERE phrase=?", (phrase,))
        self._conn.commit()

    def stats(self) -> Dict[str, Any]:
        """Return learning engine statistics."""
        c = self._conn.cursor()
        total  = c.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
        blocked_count = c.execute("SELECT COUNT(*) FROM decisions WHERE blocked=1").fetchone()[0]
        allowed_count = total - blocked_count
        fp_count = c.execute("SELECT COUNT(*) FROM decisions WHERE analyst_label='false_positive'").fetchone()[0]
        fn_count = c.execute("SELECT COUNT(*) FROM decisions WHERE analyst_label='false_negative'").fetchone()[0]
        tp_count = c.execute("SELECT COUNT(*) FROM decisions WHERE analyst_label='true_positive'").fetchone()[0]
        tn_count = c.execute("SELECT COUNT(*) FROM decisions WHERE analyst_label='true_negative'").fetchone()[0]
        correct_count = c.execute("SELECT COUNT(*) FROM decisions WHERE analyst_correct=1").fetchone()[0]
        patterns = c.execute("SELECT COUNT(*) FROM pattern_candidates WHERE confirmed=0").fetchone()[0]
        confirmed_patterns = c.execute("SELECT COUNT(*) FROM pattern_candidates WHERE confirmed=1").fetchone()[0]
        adjustments = c.execute("SELECT COUNT(*) FROM learned_score_adjustments").fetchone()[0]
        fp_memory = c.execute("SELECT COUNT(*) FROM false_positive_memory").fetchone()[0]
        # Precision/recall if enough feedback
        precision = tp_count / max(1, tp_count + fp_count)
        recall_d  = tp_count + fn_count
        recall    = tp_count / max(1, recall_d)
        f1 = (2 * precision * recall) / max(0.0001, precision + recall)
        # Recent trend (last 100)
        recent = c.execute("""
            SELECT AVG(ti_score), AVG(blocked)
            FROM (SELECT ti_score, blocked FROM decisions ORDER BY timestamp DESC LIMIT 100)
        """).fetchone()
        return {
            "total_decisions":      total,
            "blocked":              blocked_count,
            "allowed":              allowed_count,
            "true_positives":       tp_count,
            "true_negatives":       tn_count,
            "confirmed_correct":    correct_count,
            "false_positives":      fp_count,
            "false_negatives":      fn_count,
            "precision":            round(precision, 3),
            "recall":               round(recall, 3),
            "f1_score":             round(f1, 3),
            "pattern_candidates":   patterns,
            "confirmed_patterns":   confirmed_patterns,
            "score_adjustments":    adjustments,
            "fp_memory_entries":    fp_memory,
            "recent_avg_score":     round(recent[0] or 0, 1),
            "recent_block_rate":    round((recent[1] or 0) * 100, 1),
        }

    def recent_decisions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return recent decisions for dashboard display."""
        c = self._conn.cursor()
        rows = c.execute("""
            SELECT prompt_hash, prompt_excerpt, timestamp, ti_score, risk_level,
                   blocked, top_signal, attack_cats, analyst_correct, analyst_label
            FROM decisions ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
        result = []
        for r in rows:
            result.append({
                "prompt_hash":     r[0],
                "prompt_excerpt":  r[1],
                "timestamp":       r[2],
                "ti_score":        r[3],
                "risk_level":      r[4],
                "blocked":         bool(r[5]),
                "top_signal":      r[6],
                "attack_cats":     json.loads(r[7] or "[]"),
                "analyst_correct": r[8],
                "analyst_label":   r[9],
            })
        return result


class PatternLearner:
    """
    Extracts candidate injection phrases from confirmed-attack prompts.
    Uses N-gram extraction + frequency filtering to surface novel patterns.
    """

    # Minimum phrase length and token count to be a useful pattern
    MIN_TOKENS = 3
    MAX_TOKENS = 8
    MIN_CHARS  = 12

    def extract_candidates(self, prompt: str, confidence: float = 0.7) -> List[Tuple[str, float]]:
        """Extract candidate injection phrases from a confirmed-attack prompt."""
        tokens = re.findall(r"\b[a-z]{2,}\b", prompt.lower())
        candidates: List[Tuple[str, float]] = []
        for n in range(self.MIN_TOKENS, min(self.MAX_TOKENS + 1, len(tokens) + 1)):
            for i in range(len(tokens) - n + 1):
                phrase = " ".join(tokens[i:i+n])
                if len(phrase) < self.MIN_CHARS:
                    continue
                # Score by presence of high-signal vocabulary
                score = self._phrase_score(tokens[i:i+n])
                if score >= 0.5:
                    candidates.append((phrase, round(min(1.0, score * confidence), 3)))
        # Deduplicate and sort by score
        seen: Dict[str, float] = {}
        for phrase, sc in candidates:
            seen[phrase] = max(seen.get(phrase, 0), sc)
        return sorted(seen.items(), key=lambda x: -x[1])[:10]

    def _phrase_score(self, tokens: List[str]) -> float:
        HIGH = frozenset({
            "ignore", "bypass", "override", "forget", "disregard", "reveal",
            "unrestricted", "admin", "root", "developer", "system", "jailbreak",
            "pretend", "roleplay", "simulate", "no restrictions", "without limits",
            "no guidelines", "no rules", "no filters", "act as", "you are now",
            "from now on", "new instructions", "your instructions",
        })
        hits = sum(1 for t in tokens if t in HIGH)
        return hits / len(tokens)


class AdaptiveScoringLayer:
    """
    Applies learned score adjustments on top of TI engine output.
    Uses analyst feedback to nudge heuristic scores. This is not statistical
    calibration and does not retrain the local semantic model.
    """

    def __init__(self, store: FeedbackStore):
        self._store = store
        self._learner = PatternLearner()
        self._adjustments: Dict[str, float] = {}
        self._last_refresh = 0.0
        self._REFRESH_INTERVAL = 60.0  # seconds

    def _maybe_refresh(self):
        now = time.time()
        if now - self._last_refresh > self._REFRESH_INTERVAL:
            self._adjustments = self._store.get_score_adjustments()
            self._last_refresh = now

    def invalidate_adjustments(self):
        self._last_refresh = 0.0

    def apply(
        self,
        prompt: str,
        ti_result: Dict[str, Any],
        blocked: bool,
        top_signal: str,
        attack_cats: List[str],
        hard_blocked: bool = False,
        scope: str = "",
    ) -> Tuple[int, str, bool]:
        """
        Apply adaptive adjustments to the TI composite score.

        Returns: (adjusted_score, adjusted_risk_level, adjusted_blocked)
        """
        self._maybe_refresh()

        score = ti_result.get("composite_score", 0)
        risk  = ti_result.get("risk_level", "LOW")

        # 1. Check FP memory — if this exact prompt was FP before, reduce score
        if self._store.is_known_false_positive(prompt, scope=scope):
            score = max(0, score - 20)

        confirmed_attack = self._store.is_confirmed_attack(prompt, scope=scope)
        if confirmed_attack:
            score = 100

        # 2. Apply a bounded aggregate adjustment. Analyst feedback nudges
        # future heuristic scores, while exact confirmed attacks use memory.
        learned_delta = 0
        for sig in ti_result.get("signals", []):
            sig_name = sig.get("name", "")
            adj = self._adjustments.get(sig_name, 0.0)
            if adj != 0.0:
                learned_delta += int(max(-0.05, min(0.05, adj)) * 100)
        score = max(0, min(100, score + max(-5, min(5, learned_delta))))

        # 3. Re-derive risk level from adjusted score
        if confirmed_attack or score >= 75:
            risk    = "CRITICAL"
        elif score >= 50:
            risk    = "HIGH"
        elif score >= 25:
            risk = "MEDIUM"
        else:
            risk    = "LOW"

        # Scores describe risk; they are not a second, independent block rule.
        # Callers decide escalation using corroborating signal strength and
        # category count, then pass that policy decision in `blocked`.
        # Learning can preserve deterministic and confirmed-attack blocks, but
        # cannot turn one weak signal into an automatic denial.
        blocked = bool(blocked or hard_blocked or confirmed_attack)

        return score, risk, blocked

    def record_and_learn(
        self,
        prompt: str,
        ti_result: Dict[str, Any],
        blocked: bool,
        scope: str = "",
    ) -> str:
        """Record decision and extract pattern candidates from attacks."""
        top = ti_result.get("top_signal") or {}
        top_name = top.get("name", "") if isinstance(top, dict) else ""
        attack_cats = ti_result.get("attack_categories", [])
        h = self._store.record_decision(
            prompt=prompt,
            ti_score=ti_result.get("composite_score", 0),
            risk_level=ti_result.get("risk_level", "LOW"),
            blocked=blocked,
            top_signal=top_name,
            attack_cats=attack_cats,
            scope=scope,
        )
        # Extract pattern candidates from high-confidence attacks
        if blocked and ti_result.get("composite_score", 0) >= 70:
            # Candidate phrases help review novel attacks, but must never turn
            # feedback storage into a copy of a sensitive prompt.
            from app.dlp import redact_sensitive_values, scan_text
            safe_prompt = redact_sensitive_values(
                prompt, scan_text(prompt, source="prompt")
            )
            candidates = self._learner.extract_candidates(safe_prompt, confidence=0.8)
            for phrase, conf in candidates[:5]:
                self._store.add_pattern_candidate(phrase, h, conf)
        return h


def _hash_prompt(prompt: str, scope: str = "") -> str:
    """Keyed fingerprint of normalized text and actor scope."""
    normalised = re.sub(r"\s+", " ", prompt.lower().strip())
    scoped = f"{scope.casefold().strip()}\0{normalised}"
    return hmac.new(_FINGERPRINT_KEY, scoped.encode(), hashlib.sha256).hexdigest()[:16]


def _safe_excerpt(prompt: str, max_len: int = 80) -> str:
    """Legacy helper retained for compatibility; never returns prompt text."""
    return "[prompt content withheld]"


# ── Singletons ────────────────────────────────────────────────────────────────
feedback_store = FeedbackStore()
adaptive_layer = AdaptiveScoringLayer(feedback_store)
