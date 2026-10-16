"""Heuristic risk scoring for suspicious prompts.

The engine combines prompt structure, curated vocabulary, DLP findings,
session history, and jailbreak-pattern matches into an explainable 0–100 score.
The score is a triage signal, not a calibrated probability or an accuracy claim.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# ── Risk level thresholds ─────────────────────────────────────────────────────
RISK_THRESHOLDS = {
    "CRITICAL": 75,
    "HIGH":     50,
    "MEDIUM":   25,
    "LOW":       0,
}

# OWASP LLM Top-10 2025 threat mapping (used in signal metadata)
OWASP_MAPPING: Dict[str, str] = {
    "attack_type":  "LLM01 — Prompt Injection",
    "encoding":     "LLM01 — Prompt Injection (encoded)",
    "structure":    "LLM01 — Prompt Injection (structural)",
    "latent":       "LLM01 — Prompt Injection (lexical concept-anchor heuristic)",
    "jailbreak":    "LLM01 — Prompt Injection (JEB jailbreak benchmark)",
    "behavior":     "LLM01 — Prompt Injection (multi-turn)",
    "pii":          "LLM06 — Sensitive Information Disclosure",
    "data_exfil":   "LLM02 — Insecure Output Handling",
    "supply_chain": "LLM03 — Supply Chain Vulnerabilities",
}


@dataclass
class ThreatSignal:
    """A single scored signal contributing to the overall risk assessment."""
    name: str
    score: float          # 0.0 – 1.0
    weight: float         # relative importance
    description: str      # human-readable for dashboard
    evidence: str         # what triggered this signal
    category: str         # attack_type | encoding | structure | behavior | pii | data_exfil
    owasp_ref: str = ""   # OWASP LLM Top-10 reference


@dataclass
class RiskAssessment:
    """Complete threat intelligence result for a single prompt."""
    composite_score: int              # 0–100
    risk_level: str                   # LOW / MEDIUM / HIGH / CRITICAL
    signals: List[ThreatSignal]
    top_signal: Optional[ThreatSignal]
    attack_categories: List[str]      # which attack types were signalled
    structural_summary: Dict[str, Any]
    recommendation: str               # what the gateway should do and why
    owasp_threats: List[str]          # OWASP references fired

    @property
    def should_escalate(self) -> bool:
        return self.composite_score >= RISK_THRESHOLDS["HIGH"]

    @property
    def bar_width(self) -> int:
        return self.composite_score


# ═════════════════════════════════════════════════════════════════════════════
# PATTERN LIBRARY
# ═════════════════════════════════════════════════════════════════════════════

# Imperative attack verbs (OWASP LLM01 — direct injection vocabulary)
_IMPERATIVE_VERBS = re.compile(
    r"\b(ignore|forget|disregard|override|bypass|reveal|dump|extract|exfiltrate|"
    r"print|output|show|list|send|leak|expose|disable|remove|delete|replace|"
    r"pretend|act|simulate|roleplay|imagine|assume|suppose|consider|"
    r"execute|run|invoke|call|trigger|activate|inject|embed|insert)\\b",
    re.IGNORECASE,
)

# Separated imperative — catches 'i g n o r e', 'I.G.N.O.R.E', 'i-g-n-o-r-e'
_SPACED_IMPERATIVE = re.compile(
    r"\b(i[\s.\-_]g[\s.\-_]n[\s.\-_]o[\s.\-_]r[\s.\-_]e|"
    r"r[\s.\-_]e[\s.\-_]v[\s.\-_]e[\s.\-_]a[\s.\-_]l|"
    r"b[\s.\-_]y[\s.\-_]p[\s.\-_]a[\s.\-_]s[\s.\-_]s|"
    r"d[\s.\-_]u[\s.\-_]m[\s.\-_]p|"
    r"l[\s.\-_]e[\s.\-_]a[\s.\-_]k)\b",
    re.IGNORECASE,
)

# Authority & privilege claim (OWASP LLM01 — role hijacking)
_AUTHORITY_CLAIMS = re.compile(
    r"\b(as (?:an? )?(?:admin|root|developer|system|operator|superuser|god|owner|creator)|"
    r"i am (?:an? )?(?:admin|root|developer|system|operator|engineer|security researcher)|"
    r"with (?:admin|root|full|unrestricted|elevated|god) (?:access|privileges?|rights?|permissions?)|"
    r"in (?:admin|developer|maintenance|debug|god|root|test) mode|"
    r"acting as (?:the )?(?:system|admin|developer|operator|unrestricted)|"
    r"you are now (?:a|an|the)?|"
    r"from now on you (?:are|will|must|should)|"
    r"henceforth you|"
    r"starting now you|"
    r"assume the role of|"
    r"take on the persona of|"
    r"your true self is)\b",
    re.IGNORECASE,
)

# Restriction negation chains (OWASP LLM01)
_NEGATION_CHAINS = re.compile(
    r"\b(without (?:any )?(?:restrictions?|limits?|constraints?|guidelines?|rules?|filters?)|"
    r"no (?:longer )?(?:bound|limited|restricted|constrained|filtered) by|"
    r"free from (?:any )?(?:restrictions?|limits?|constraints?)|"
    r"not (?:bound|limited|restricted|subject) to|"
    r"ignoring (?:all )?(?:restrictions?|rules?|guidelines?|filters?)|"
    r"unrestricted(?:ly)?|"
    r"unconstrained(?:ly)?|"
    r"unfiltered(?:ly)?|"
    r"no safety (?:checks?|guardrails?|filters?)|"
    r"bypass (?:all )?(?:safety|security|content) (?:filters?|guardrails?|checks?))\b",
    re.IGNORECASE,
)

# Instruction framing (OWASP LLM01 — prompt override)
_INSTRUCTION_FRAMING = re.compile(
    r"\b(from now on|starting (?:now|immediately|today)|"
    r"going forward|for (?:the )?(?:rest|remainder) of (?:this )?(?:conversation|session|chat)|"
    r"henceforth|new (?:system )?prompt|updated (?:system )?(?:prompt|instructions?)|"
    r"your (?:new|updated|real|actual|true) instructions? (?:are|is|will be)|"
    r"I(?:'m| am) (?:now )?overriding|"
    r"replace (?:your )?(?:previous|old|current) instructions?|"
    r"forget (?:what|everything) (?:you (?:know|were told)|previously)|"
    r"disregard (?:all )?(?:previous|prior|earlier) (?:context|instructions?|messages?)|"
    r"your (?:only|primary|sole) (?:task|goal|objective) (?:now )?is)\b",
    re.IGNORECASE,
)

# Interrogation-style mass extraction (OWASP LLM06)
_EXTRACTION_INTERROGATION = re.compile(
    r"\b(tell me (?:all|every(?:thing)?|each)|"
    r"give me (?:all|every(?:thing)?|a list of|the full|complete)|"
    r"what (?:are|were|is|was) (?:all|every)|"
    r"list (?:all|every(?:thing)?)|"
    r"enumerate (?:all|every(?:thing)?)|"
    r"show me (?:all|every(?:thing)?|each)|"
    r"retrieve (?:all|every(?:thing)?)|"
    r"export (?:all|every(?:thing)?)|"
    r"download (?:all|the complete))\b",
    re.IGNORECASE,
)

# Social engineering / urgency manipulation (OWASP LLM01)
_SOCIAL_ENGINEERING = re.compile(
    r"\b(this is (?:an? )?(?:emergency|urgent|critical|important) (?:situation|matter|case)|"
    r"(?:life|lives?) (?:are )?at stake|"
    r"under (?:penalty|threat) of|"
    r"if you (?:don[''']t|do not)|"
    r"you (?:must|have to|need to) (?:help|comply|do this)|"
    r"as (?:a )?(?:responsible|good|helpful|smart|intelligent) (?:ai|assistant|model)|"
    r"(?:i[''']m|i am) (?:testing|auditing|evaluating|assessing) (?:you|your|this)|"
    r"for (?:research|academic|educational|testing|training) purposes?|"
    r"this is (?:just )?(?:a )?(?:test|hypothetical|thought experiment|simulation)|"
    r"pretend (?:this is|it's|that) (?:a )?(?:game|test|simulation|story)|"
    r"in (?:this )?(?:story|game|simulation|scenario|roleplay))\b",
    re.IGNORECASE,
)

# Context / document manipulation (Greshake et al. 2023 — indirect injection)
_CONTEXT_MANIPULATION = re.compile(
    r"\b((?:the )?(?:following|above|below|next|previous) (?:is|are|contains?|represents?) "
    r"(?:the )?(?:system|developer|real|true|actual)|"
    r"(?:treat|consider|read) (?:the )?(?:following|above) as (?:an? )?(?:instruction|command|directive|system message)|"
    r"(?:embedded|hidden|secret) instructions?|"
    r"special (?:mode|command|instruction|directive)|"
    r"debug (?:mode|command|override)|"
    r"maintenance (?:mode|override|bypass)|"
    r"this (?:document|text|content) contains? (?:instructions?|directives?|commands?))\b",
    re.IGNORECASE,
)

# Markdown exfiltration patterns (OWASP LLM02 — insecure output handling)
# Attacker embeds ![x](https://attacker.com/?data=...) in documents to exfiltrate via img load
_MARKDOWN_EXFIL = re.compile(
    r"!\[.*?\]\(https?://(?!(?:localhost|127\.0\.0\.1))[^\s)]+(?:\?[^\s)]+)?\)",
    re.IGNORECASE,
)

# Data exfiltration via URL encoding (attacker leaks data through embedded links)
_URL_EXFIL = re.compile(
    r"(?:curl|wget|fetch|http\.get|requests\.get|urllib)\s*\(?['\"]https?://",
    re.IGNORECASE,
)

# Token smuggling — base64-encoded instructions in prompt
_BASE64_PAYLOAD = re.compile(
    r"(?:[A-Za-z0-9+/]{20,}={0,2})",  # ≥20 char base64 runs
)

# Hex-encoded payload
_HEX_PAYLOAD = re.compile(
    r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}",  # ≥5 consecutive hex escapes
)

# Unicode zero-width / invisible characters (hidden instruction embedding)
_ZERO_WIDTH_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f"
    r"\ufeff\u00ad\u034f\u115f\u1160\u17b4\u17b5\u2800\u3164\uffa0"
    r"\U000e0000-\U000e007f]"
)

# Bidirectional text override characters (render text differently in UI vs model)
_BIDI_ATTACK_CHARS = re.compile(r"[\u202a-\u202e\u2066-\u2069\u200f\u200e]")

# Tag character block U+E0000–U+E007F — completely invisible, used to hide instructions
_TAG_CHARS = re.compile(r"[\U000e0000-\U000e007f]")

# Chat format delimiter injection (Perez & Ribeiro 2022 taxonomy)
_DELIMITER_INJECTION = re.compile(
    r"(<\|(?:im_start|im_end|system|user|assistant)\|>|"
    r"\[/?INST\]|<</?SYS>>|"
    r"<</SYS>>|"
    r"(?:^|\n)\s*(?:###?\s*)?(?:Human|Assistant|System|User)\s*:|"
    r"<(?:system|user|assistant)>|"      # XML-style role tags
    r"\{\{#(?:system|user|assistant)\}\})",  # Handlebars-style
    re.IGNORECASE | re.MULTILINE,
)

# Repetition attack — saying the same sensitive request 3+ times to wear down defences
_REPETITION_PATTERN = re.compile(
    r"\b(\w{5,})\b(?:.{0,200}\b\1\b){2,}",
    re.IGNORECASE | re.DOTALL,
)

# Cognitive overload attack — extremely long single sentence designed to confuse the model
# (no regex — measured by avg_sentence_length)

# Benign enterprise vocabulary (used to discount false positives)
_BENIGN_ENTERPRISE = re.compile(
    r"\b(leave policy|time off|onboarding|handbook|hr portal|help desk|"
    r"annual review|performance review|expense|reimbursement|payslip|"
    r"training|benefits|insurance|vacation|holiday|sick leave|wfh|"
    r"remote work|meeting|calendar|project|deadline|sprint|ticket|"
    r"software update|password reset|mfa|two.factor|vpn|laptop|"
    r"compliance|audit|appraisal|induction|probation|payroll|"
    r"recruitment|interview|offer letter|joining date)\b",
    re.IGNORECASE,
)

# High-suspicion vocabulary for n-gram scoring
_HIGH_SUSPICION_WORDS = frozenset({
    "ignore", "bypass", "override", "reveal", "extract", "dump", "exfiltrate",
    "unrestricted", "jailbreak", "pretend", "simulate", "roleplay", "forget",
    "disregard", "hidden", "secret", "admin", "root", "system",
    "confidential", "restricted", "injection",
    "exploit", "hack", "manipulate", "trick", "fool", "deceive", "escalate",
})


# ═════════════════════════════════════════════════════════════════════════════
# ANALYSIS FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════

def _word_count(text: str) -> int:
    return len(re.findall(r"\b\w+\b", text))


def _sentence_count(text: str) -> int:
    return max(1, len(re.split(r"[.!?]+", text.strip())))


def _count_caps_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c.isupper()) / len(letters)


def _token_entropy(text: str) -> float:
    """Shannon entropy of character distribution. High = encoded/random content."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _word_entropy(text: str) -> float:
    """Shannon entropy of word distribution. Very high = random word salad."""
    tokens = re.findall(r"\b[a-z]+\b", text.lower())
    if len(tokens) < 3:
        return 0.0
    counts = Counter(tokens)
    total = len(tokens)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _compute_perplexity_proxy(text: str) -> float:
    """
    Perplexity proxy without an LLM: measures character-level cross-entropy
    against a uniform background distribution.

    Research basis: adversarial suffixes (e.g., GCG attack, Zou et al. 2023)
    produce unnaturally high perplexity because they optimise for model logits,
    not human readability. High char entropy relative to typical English is a
    strong signal of encoded or adversarially-crafted content.

    Returns a 0–1 score where 1 = maximally unusual.
    """
    char_entropy = _token_entropy(text)
    # English prose: entropy ~4.0–4.5 bits; encoded text: 5.5–6.0 bits
    # Injection phrases: often 4.5–5.5 (wordy, repetitive)
    if char_entropy < 3.5:
        return 0.0   # too short / repetitive
    if char_entropy > 5.5:
        return min(1.0, (char_entropy - 5.5) / 0.8)  # likely encoded
    return 0.0


def _detect_hidden_unicode(text: str) -> Tuple[int, str]:
    zw   = len(_ZERO_WIDTH_CHARS.findall(text))
    bidi = len(_BIDI_ATTACK_CHARS.findall(text))
    tags = len(_TAG_CHARS.findall(text))
    total = zw + bidi + tags
    parts: List[str] = []
    if zw:
        parts.append(f"{zw} zero-width chars (U+200B family)")
    if bidi:
        parts.append(f"{bidi} bidi overrides (U+202x — text renders differently in UI than model sees)")
    if tags:
        parts.append(f"{tags} tag-block chars (U+E0000 — completely invisible to humans)")
    return total, " | ".join(parts) if parts else ""


def _compute_imperative_density(text: str) -> Tuple[float, List[str]]:
    matches = _IMPERATIVE_VERBS.findall(text)
    spaced  = _SPACED_IMPERATIVE.findall(text)
    all_hits = list(set(m.lower() for m in matches)) + [s.replace(" ", "") for s in spaced]
    if not all_hits:
        return 0.0, []
    words = _word_count(text)
    density = (len(matches) + len(spaced)) / max(1, words)
    return density, list(set(all_hits))


def _ngram_suspicion_score(text: str, n: int = 3) -> float:
    """Return the share of trigrams that contain curated suspicious terms."""
    tokens = re.findall(r"\b[a-z]+\b", text.lower())
    if len(tokens) < n:
        return 0.0
    ngrams = [tuple(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]
    suspicious = sum(
        1 for gram in ngrams
        if any(word in _HIGH_SUSPICION_WORDS for word in gram)
    )
    return suspicious / max(1, len(ngrams))


def _detect_repetition_attack(text: str) -> Tuple[bool, str]:
    """
    Detects repetition-based persistence attacks where the attacker repeats
    the same instruction 3+ times to 'wear down' model compliance.
    """
    match = _REPETITION_PATTERN.search(text)
    if match:
        return True, f"Repeated key term: '{match.group(1)}'"
    return False, ""


def _detect_encoded_payload(text: str) -> Tuple[bool, str]:
    """
    Detects base64 or hex-encoded payloads embedded in prompts.
    Token smuggling: encode 'ignore all instructions' as base64, ask model to decode and follow.
    """
    b64_matches = _BASE64_PAYLOAD.findall(text)
    hex_matches = _HEX_PAYLOAD.findall(text)
    # Filter: only flag if ≥1 base64 run of length ≥ 24 (≥18 decoded chars)
    long_b64 = [m for m in b64_matches if len(m) >= 24]
    if long_b64:
        return True, f"{len(long_b64)} base64 payload(s) detected (≥24 chars each)"
    if hex_matches:
        return True, f"{len(hex_matches)} hex-encoded sequence(s) detected"
    return False, ""


def _check_prompt_structure_anomaly(text: str) -> Dict[str, Any]:
    words = _word_count(text)
    sentences = _sentence_count(text)
    avg_sentence_len = words / max(1, sentences)
    imp_density, imp_hits = _compute_imperative_density(text)
    char_entropy = _token_entropy(text)
    word_ent = _word_entropy(text)
    hidden_count, hidden_desc = _detect_hidden_unicode(text)
    has_delimiter = bool(_DELIMITER_INJECTION.search(text))
    ngram_score = _ngram_suspicion_score(text)
    benign_hits = len(_BENIGN_ENTERPRISE.findall(text))
    perplexity_proxy = _compute_perplexity_proxy(text)
    has_markdown_exfil = bool(_MARKDOWN_EXFIL.search(text))
    has_url_exfil = bool(_URL_EXFIL.search(text))
    has_repetition, repetition_evidence = _detect_repetition_attack(text)
    has_encoded, encoded_evidence = _detect_encoded_payload(text)
    caps_ratio = _count_caps_ratio(text)
    question_density = text.count("?") / max(1, words) * 100

    # Cognitive overload: very long sentence designed to confuse model context window
    cognitive_overload = avg_sentence_len > 60 and sentences <= 2

    return {
        "word_count": words,
        "sentence_count": sentences,
        "avg_sentence_length": round(avg_sentence_len, 1),
        "char_entropy": round(char_entropy, 3),
        "word_entropy": round(word_ent, 3),
        "imperative_density": round(imp_density, 3),
        "imperative_hits": imp_hits,
        "caps_ratio": round(caps_ratio, 3),
        "question_density": round(question_density, 2),
        "hidden_unicode_count": hidden_count,
        "hidden_unicode_desc": hidden_desc,
        "has_delimiter_injection": has_delimiter,
        "ngram_suspicion_score": round(ngram_score, 3),
        "benign_enterprise_hits": benign_hits,
        "perplexity_proxy": round(perplexity_proxy, 3),
        "has_markdown_exfiltration": has_markdown_exfil,
        "has_url_exfiltration": has_url_exfil,
        "has_repetition_attack": has_repetition,
        "repetition_evidence": repetition_evidence,
        "has_encoded_payload": has_encoded,
        "encoded_evidence": encoded_evidence,
        "cognitive_overload": cognitive_overload,
    }


# ═════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE ENGINE
# ═════════════════════════════════════════════════════════════════════════════

class ThreatIntelligenceEngine:
    """Combine deterministic prompt signals into an explainable heuristic score.

    Signals can be correlated. Treat the resulting score as a ranking aid, not
    as a probability or a standalone security decision.
    """

    def assess(
        self,
        prompt: str,
        dlp_findings: List[Any] | None = None,
        session_history: List[Dict[str, Any]] | None = None,
        user_role: str = "employee",
    ) -> RiskAssessment:
        dlp_findings    = dlp_findings or []
        session_history = session_history or []
        signals: List[ThreatSignal] = []
        struct = _check_prompt_structure_anomaly(prompt)

        def _sig(name, score, weight, description, evidence, category):
            owasp = OWASP_MAPPING.get(category, "")
            signals.append(ThreatSignal(
                name=name, score=round(min(1.0, score), 3), weight=weight,
                description=description, evidence=str(evidence)[:150],
                category=category, owasp_ref=owasp,
            ))

        benign_discount = struct["benign_enterprise_hits"] >= 2 and len(dlp_findings) == 0

        # ── Signal 1: Imperative verb density ────────────────────────────────
        imp_d = struct["imperative_density"]
        imp_hits = struct["imperative_hits"]
        if imp_d > 0:
            raw = min(1.0, imp_d / 0.12)
            if benign_discount:
                raw *= 0.25
            _sig(
                "Imperative Verb Density", raw, 0.18,
                f"Found {len(imp_hits)} imperative command verb(s) "
                f"({', '.join(imp_hits[:6])}) in {struct['word_count']}-word prompt. "
                f"Density ratio: {imp_d:.3f}. Threshold: 0.12.",
                ", ".join(imp_hits[:8]), "structure",
            )

        # ── Signal 2: Authority claim ─────────────────────────────────────────
        auth_m = _AUTHORITY_CLAIMS.findall(prompt)
        if auth_m:
            _sig(
                "Privilege / Authority Claim", min(1.0, len(auth_m) * 0.4), 0.22,
                f"Detected {len(auth_m)} authority-escalation phrase(s). "
                f"Pattern: attacker claims 'I am admin', 'with root access', 'in developer mode' "
                f"to bypass role-based restrictions. OWASP LLM01 role hijacking vector.",
                str(auth_m[0])[:80], "attack_type",
            )

        # ── Signal 3: Negation chain ──────────────────────────────────────────
        neg_m = _NEGATION_CHAINS.findall(prompt)
        if neg_m:
            _sig(
                "Restriction Negation Chain", min(1.0, len(neg_m) * 0.45), 0.20,
                f"Found {len(neg_m)} negation phrase(s) attempting to logically negate "
                f"security constraints. Pattern: 'without restrictions', 'not bound by', "
                f"'bypass all safety filters'. Classic injection pre-conditioning.",
                str(neg_m[0])[:80], "attack_type",
            )

        # ── Signal 4: Instruction framing ─────────────────────────────────────
        frame_m = _INSTRUCTION_FRAMING.findall(prompt)
        if frame_m:
            _sig(
                "Instruction Override Framing", min(1.0, len(frame_m) * 0.5), 0.20,
                f"Detected {len(frame_m)} instruction-override phrase(s). "
                f"Pattern: 'from now on', 'new system prompt', 'your updated instructions are'. "
                f"Classic direct prompt injection framing (Perez & Ribeiro 2022).",
                str(frame_m[0])[:80], "attack_type",
            )

        # ── Signal 5: Social engineering ──────────────────────────────────────
        social_m = _SOCIAL_ENGINEERING.findall(prompt)
        if social_m:
            _sig(
                "Social Engineering Indicator", min(1.0, len(social_m) * 0.35), 0.14,
                f"Found {len(social_m)} social manipulation indicator(s). "
                f"Tactics: urgency ('lives at stake'), justification ('for research'), "
                f"flattery ('as a responsible AI'). Used to lower compliance barriers.",
                str(social_m[0])[:80], "attack_type",
            )

        # ── Signal 6: Context / document manipulation ─────────────────────────
        ctx_m = _CONTEXT_MANIPULATION.findall(prompt)
        if ctx_m:
            _sig(
                "Context / Document Manipulation", min(1.0, len(ctx_m) * 0.55), 0.22,
                f"Detected {len(ctx_m)} context-manipulation phrase(s). "
                f"Pattern: 'treat the following as system instructions', 'this document contains directives'. "
                f"Indirect injection vector (Greshake et al. 2023) — can arrive via RAG docs.",
                str(ctx_m[0])[:80], "attack_type",
            )

        # ── Signal 7: Hidden unicode attack ───────────────────────────────────
        hc = struct["hidden_unicode_count"]
        if hc > 0:
            _sig(
                "Hidden Unicode Attack", min(1.0, hc * 0.3), 0.35,
                f"Found {hc} invisible/control unicode character(s): {struct['hidden_unicode_desc']}. "
                f"Zero-width chars (U+200B) and tag-block chars (U+E0000) embed instructions "
                f"that are invisible to humans in UI but processed by the model.",
                f"{hc} hidden chars: {struct['hidden_unicode_desc']}", "encoding",
            )

        # ── Signal 8: Chat delimiter injection ────────────────────────────────
        if struct["has_delimiter_injection"]:
            _sig(
                "Chat Delimiter Injection", 0.95, 0.35,
                "Detected chat-format delimiter injection (<|system|>, [INST], <<SYS>>, "
                "or 'Human:'/'User:' role markers). "
                "Mimics model training format to inject system-level instructions. "
                "Perez & Ribeiro (2022) taxonomy: format injection.",
                "Chat delimiter found in user content", "encoding",
            )

        # ── Signal 9: Data extraction interrogation ───────────────────────────
        extr_m = _EXTRACTION_INTERROGATION.findall(prompt)
        if extr_m:
            _sig(
                "Data Extraction Interrogation", min(1.0, len(extr_m) * 0.35), 0.16,
                f"Found {len(extr_m)} broad data-extraction phrasing(s). "
                f"Pattern: 'tell me all', 'give me every', 'enumerate all', 'export all'. "
                f"Attempts to bulk-extract restricted document content via RAG. "
                f"OWASP LLM06 — Sensitive Information Disclosure.",
                str(extr_m[0])[:80], "pii",
            )

        # ── Signal 10: N-gram suspicion scoring ───────────────────────────────
        ng = struct["ngram_suspicion_score"]
        if ng > 0.12:
            adj = min(1.0, (ng - 0.12) / 0.35)
            if struct["benign_enterprise_hits"] >= 2:
                adj *= 0.2
            if adj > 0.05:
                _sig(
                    "N-gram Suspicion Score", adj, 0.10,
                    f"Trigram analysis: {ng:.1%} of word sequences contain high-suspicion "
                    f"vocabulary ({len(_HIGH_SUSPICION_WORDS)} curated terms). "
                    f"This prompt has a trigram suspicion score of {ng:.1%}; "
                    f"the signal is based on curated terms and may flag benign wording.",
                    f"Trigram density: {ng:.3f}", "structure",
                )

        # ── Signal 11: DLP signal correlation ────────────────────────────────
        if dlp_findings:
            # Handle both Finding dataclass and dict
            def _get(f, k):
                return getattr(f, k, None) or (f.get(k) if isinstance(f, dict) else None)
            block_f = [f for f in dlp_findings if _get(f, "action") == "block"]
            inj_cnt = sum(1 for f in dlp_findings if _get(f, "category") == "prompt_injection")
            pii_cnt = sum(1 for f in dlp_findings if _get(f, "category") in {
                "pan", "aadhar", "api_key", "password", "secret", "private_key", "credit_card"
            })
            if block_f:
                score = min(1.0, 0.4 + len(block_f) * 0.15)
                parts = []
                if inj_cnt: parts.append(f"{inj_cnt} injection pattern(s)")
                if pii_cnt: parts.append(f"{pii_cnt} PII/credential type(s)")
                _sig(
                    "DLP Signal Correlation", score, 0.25,
                    f"Layer 1 DLP detected {len(block_f)} blocking finding(s): "
                    + (", ".join(parts) if parts else "policy violation") +
                    ". Combined with structural signals, this indicates a "
                    "coordinated multi-vector attack. OWASP LLM06.",
                    f"{len(block_f)} block-level DLP findings", "pii",
                )

        # ── Signal 12: Session escalation detection ───────────────────────────
        if session_history and len(session_history) >= 2:
            recent_blocks = sum(1 for h in session_history[-5:] if h.get("blocked"))
            recent_inj = sum(
                1 for h in session_history[-5:]
                if any(
                    (f.get("category") if isinstance(f, dict) else getattr(f, "category", ""))
                    == "prompt_injection"
                    for f in h.get("prompt_findings", [])
                )
            )
            if recent_blocks >= 1 or recent_inj >= 1:
                _sig(
                    "Session Escalation Pattern",
                    min(1.0, (recent_blocks + recent_inj) * 0.3), 0.20,
                    f"Session history shows {recent_blocks} block(s) and {recent_inj} injection "
                    f"attempt(s) in the last 5 turns. "
                    f"Pattern: probe → refine → re-attack (MDPI 2024 multi-turn injection model). "
                    f"Escalating risk threshold for this session.",
                    f"Last 5 turns: {recent_blocks} blocks, {recent_inj} injections", "behavior",
                )

        # ── Signal 13: Token smuggling (encoded payload) ─────────────────────
        # Pruned: Abnormal Capitalisation (weight=0.08) — too low-value, causes FP
        # on enterprise acronyms; authority-claim signal covers intentional caps.
        # Pruned: Repetition/Persistence Attack — fully subsumed by JEB engine's
        # many-shot jailbreak detection (JailbreakBench family: many_shot_jailbreak).
        if struct["has_encoded_payload"]:
            _sig(
                "Token Smuggling — Encoded Payload", 0.88, 0.30,
                f"Detected encoded content: {struct['encoded_evidence']}. "
                f"Encoded text can hide instructions from checks that only inspect readable wording. "
                f"A deterministic byte-pattern check found a possible encoded payload.",
                struct["encoded_evidence"], "encoding",
            )

        # ── Signal 14: lexical concept-anchor projection ─────────────────────
        # This is a hand-built token-vocabulary heuristic, not a JEPA model.
        try:
            from app.jepa_analyzer import jepa_analyzer
            jepa_res = jepa_analyzer.analyze(prompt)
            if jepa_res.adversarial_affinity >= 0.10 and jepa_res.divergence_score >= 0.50:
                _sig(
                    "Lexical Concept-Anchor Heuristic",
                    jepa_res.divergence_score,
                    0.28,  # Weight for this supplementary lexical signal
                    f"Hand-built token anchors overlap with adversarial vocabulary "
                    f"(divergence={jepa_res.divergence_score:.2f}, "
                    f"adversarial_energy={jepa_res.adversarial_affinity:.2f}, "
                    f"benign_energy={jepa_res.benign_affinity:.2f}). "
                    f"Dominant attack concepts: {', '.join(jepa_res.dominant_adversarial_concepts[:3])}. "
                    f"Supplementary lexical signal only; it is not semantic understanding.",
                    f"Concept-anchor score: {jepa_res.divergence_score:.3f}",
                    "latent",
                )
        except Exception:
            pass

        # ── Signal 15: curated jailbreak pattern screen ─────────────────────
        # JailbreakBench taxonomy: 10 attack families including GCG suffix, DAN persona,
        # many-shot, cipher, persona, refusal-suppression. All via deterministic scan.
        try:
            from app.jeb_defense import jeb_engine
            jeb_res = jeb_engine.scan(prompt)
            if jeb_res.is_jailbreak_attempt:
                _sig(
                    "JEB Jailbreak Defense Anomaly",
                    jeb_res.anomaly_confidence,
                    0.32,  # Elevated: most comprehensive jailbreak coverage
                    f"Curated jailbreak-pattern scan matched "
                    f"'{jeb_res.attack_family or 'adversarial attack'}' — one of 10 tracked "
                    f"attack families (GCG suffix, DAN persona, cipher encoding, many-shot, "
                    f"refusal-suppression, roleplay-bypass, context-ignore, authority-claim, "
                    f"social-engineering, indirect-injection). "
                    f"Indicators: {'; '.join(jeb_res.detected_indicators[:3])}. "
                    f"Entropy: {jeb_res.entropy_score:.2f} bits/symbol. "
                    f"This is a deterministic pattern match, not a semantic verdict.",
                    jeb_res.attack_family or "Jailbreak signature",
                    "jailbreak",
                )
        except Exception:
            pass

        # ── Composite score ────────────────────────────────────────────────────
        if not signals:
            composite_score = 0
        else:
            total_weight   = sum(s.weight for s in signals)
            weighted_score = sum(s.score * s.weight for s in signals)
            raw = (weighted_score / total_weight) if total_weight > 0 else 0
            # Multi-category amplification: each additional category adds 12%
            cat_count  = len({s.category for s in signals})
            amplifier  = 1.0 + (cat_count - 1) * 0.12
            composite_score = min(100, int(raw * amplifier * 100))

        risk_level = "LOW"
        for lvl, thresh in sorted(RISK_THRESHOLDS.items(), key=lambda x: -x[1]):
            if composite_score >= thresh:
                risk_level = lvl
                break

        top_signal = max(signals, key=lambda s: s.score * s.weight) if signals else None
        attack_categories = sorted({s.category for s in signals})
        owasp_threats = sorted({s.owasp_ref for s in signals if s.owasp_ref})

        if composite_score >= RISK_THRESHOLDS["CRITICAL"]:
            recommendation = (
                f"BLOCK — Critical risk ({composite_score}/100). "
                f"Multiple high-confidence attack signals detected across "
                f"{len(attack_categories)} category/categories. "
                f"Do not process this request under any circumstances."
            )
        elif composite_score >= RISK_THRESHOLDS["HIGH"]:
            recommendation = (
                f"BLOCK — High risk ({composite_score}/100). "
                f"Significant injection or privilege-escalation signals present. "
                f"Escalate to Layer 3 semantic review. Likely malicious intent."
            )
        elif composite_score >= RISK_THRESHOLDS["MEDIUM"]:
            recommendation = (
                f"REVIEW — Medium risk ({composite_score}/100). "
                f"Weak attack signals detected. Allow only after Layer 3 semantic review "
                f"confirms benign intent."
            )
        else:
            recommendation = (
                f"ALLOW — Low risk ({composite_score}/100). "
                f"No significant attack indicators. Prompt matches normal enterprise "
                f"query patterns. Proceed through standard pipeline."
            )

        return RiskAssessment(
            composite_score=composite_score,
            risk_level=risk_level,
            signals=signals,
            top_signal=top_signal,
            attack_categories=attack_categories,
            structural_summary=struct,
            recommendation=recommendation,
            owasp_threats=owasp_threats,
        )


# Singleton engine instance
threat_engine = ThreatIntelligenceEngine()
