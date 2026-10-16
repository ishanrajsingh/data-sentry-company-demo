"""
Data Sentry lexical concept-anchor heuristic
===========================================
This is a small, hand-built token-count feature projection over curated benign
and adversarial vocabularies. It is not a trained embedding model, a JEPA
implementation, or a semantic classifier. It is a cheap supplementary signal;
lexical paraphrases and unseen vocabulary can evade or confuse it.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple
import numpy as np


# ── Latent Semantic Feature Concept Vocabularies ──────────────────────────────
# Orthogonal semantic anchor concepts across enterprise vs adversarial intent

BENIGN_ENTERPRISE_ANCHORS: List[List[str]] = [
    ["leave", "vacation", "holiday", "pto", "absence", "timeoff", "calendar", "sick"],
    ["handbook", "onboarding", "policy", "guidelines", "compliance", "training", "checklist"],
    ["escalate", "support", "ticket", "customer", "workflow", "resolution", "inquiry"],
    ["summary", "summarize", "overview", "minutes", "recap", "agenda", "brief"],
    ["benefits", "insurance", "health", "wellness", "retirement", "pension", "enrollment"],
    ["meeting", "schedule", "booking", "room", "calendar", "organize", "invite"],
    ["safety", "ergonomic", "office", "equipment", "facilities", "maintenance", "chair"],
    ["purchase", "procurement", "vendor", "invoice", "receipt", "approval", "expense"],
    ["code", "repository", "commit", "review", "refactor", "bugfix", "deployment"],
    ["project", "milestone", "deliverable", "sprint", "standup", "handoff", "roadmap"],
    ["briefing", "presentation", "internal", "document", "documentation", "prepare", "draft"],
    ["password", "hygiene", "security", "best", "practices", "help", "faq", "safety"],
]

ADVERSARIAL_JAILBREAK_ANCHORS: List[List[str]] = [
    ["ignore", "disregard", "forget", "override", "bypass", "negate", "dismiss"],
    ["system", "prompt", "developer", "instructions", "hidden", "rules"],
    ["reveal", "leak", "dump", "exfiltrate", "output", "print", "extract", "show"],
    ["jailbreak", "dan", "chaosgpt", "unchained", "unrestricted", "evil", "freed"],
    ["secret", "credential", "password", "token", "apikey", "private", "confidential"],
    ["delimiter", "markdown", "image", "curl", "webhook", "exfil", "base64", "rot13"],
    ["act", "pretend", "roleplay", "simulate", "imagine", "persona", "character"],
    ["hypothetical", "fictional", "unconstrained", "bypass", "unfiltered", "raw"],
    ["salary", "compensation", "payroll", "executive", "bonus", "earnings", "ssn"],
    ["override", "precedence", "supersede", "priorities", "master", "root", "admin"],
]

_ADV_OPERATORS = frozenset({
    "ignore", "disregard", "forget", "override", "bypass", "negate", "dismiss",
    "reveal", "dump", "exfiltrate", "leak", "dan", "jailbreak", "chaosgpt",
    "unchained", "unrestricted", "precedence", "supersede", "delimiter",
})


@dataclass
class JEPAResult:
    """Output of the lexical concept-anchor heuristic."""
    latent_energy: float             # -1.0 (strongly benign) to +1.0 (strongly adversarial)
    divergence_score: float          # Normalized 0.0 to 1.0 (0=safe, 1=attack)
    benign_affinity: float           # 0.0 to 1.0
    adversarial_affinity: float      # 0.0 to 1.0
    predicted_intent_class: str      # "BENIGN_ENTERPRISE" | "AMBIGUOUS" | "ADVERSARIAL_INJECTION"
    dominant_adversarial_concepts: List[str]
    dominant_benign_concepts: List[str]
    is_adversarial: bool
    latency_ms: float
    implementation_note: str = "CPU lexical concept-anchor heuristic; not a trained JEPA model"


class JEPALatentAnalyzer:
    """
    Legacy class name retained for compatibility; this is a lexical heuristic.
    """

    def __init__(self):
        # Build vocabulary dimension
        self.benign_vocab = [term for cluster in BENIGN_ENTERPRISE_ANCHORS for term in cluster]
        self.adv_vocab = [term for cluster in ADVERSARIAL_JAILBREAK_ANCHORS for term in cluster]
        self.vocab = sorted(list(set(self.benign_vocab + self.adv_vocab)))
        self.v_dim = len(self.vocab)
        self.term_to_idx = {term: idx for idx, term in enumerate(self.vocab)}

        # Precompute projection subspace bases (orthonormalized)
        self.B_subspace = self._build_subspace_basis(BENIGN_ENTERPRISE_ANCHORS)
        self.A_subspace = self._build_subspace_basis(ADVERSARIAL_JAILBREAK_ANCHORS)

    def _build_subspace_basis(self, anchor_clusters: List[List[str]]) -> np.ndarray:
        """Construct orthonormal basis vectors for an intent manifold."""
        vectors = []
        for cluster in anchor_clusters:
            vec = np.zeros(self.v_dim, dtype=np.float32)
            for term in cluster:
                if term in self.term_to_idx:
                    vec[self.term_to_idx[term]] = 1.0
            norm = np.linalg.norm(vec)
            if norm > 1e-6:
                vec = vec / norm
                vectors.append(vec)
        
        # Gram-Schmidt orthonormalization
        basis = []
        for v in vectors:
            w = v.copy()
            for u in basis:
                w -= np.dot(w, u) * u
            norm = np.linalg.norm(w)
            if norm > 1e-4:
                basis.append(w / norm)
        
        if not basis:
            return np.zeros((1, self.v_dim), dtype=np.float32)
        return np.array(basis, dtype=np.float32)  # shape (K, V)

    def _embed_prompt(self, text: str) -> np.ndarray:
        """Project token counts onto hand-authored lexical concept anchors."""
        tokens = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
        vec = np.zeros(self.v_dim, dtype=np.float32)
        if not tokens:
            return vec
        
        counts = {}
        for t in tokens:
            counts[t] = counts.get(t, 0) + 1
            
        for term, cnt in counts.items():
            if term in self.term_to_idx:
                idx = self.term_to_idx[term]
                # Sub-linear term frequency scaling
                tf = 1.0 + math.log(cnt)
                vec[idx] = tf
                
        # Also check bigrams/synonyms
        text_lower = text.lower()
        if "system prompt" in text_lower and "system" in self.term_to_idx:
            vec[self.term_to_idx["system"]] += 2.0
        if "ignore previous" in text_lower and "ignore" in self.term_to_idx:
            vec[self.term_to_idx["ignore"]] += 2.0
        if "developer mode" in text_lower and "developer" in self.term_to_idx:
            vec[self.term_to_idx["developer"]] += 2.0
            
        norm = np.linalg.norm(vec)
        if norm > 1e-6:
            vec = vec / norm
        return vec

    def project(self, z: np.ndarray, basis: np.ndarray) -> Tuple[np.ndarray, float]:
        """Compute orthogonal projection of z onto basis and return (projection, energy/norm)."""
        if basis.shape[0] == 0 or np.linalg.norm(z) < 1e-6:
            return np.zeros_like(z), 0.0
        # coeffs = B @ z
        coeffs = np.dot(basis, z)
        # proj = coeffs @ B
        proj = np.dot(coeffs, basis)
        energy = float(np.sum(coeffs ** 2))
        return proj, energy

    def analyze(self, prompt: str) -> JEPAResult:
        """
        Return a low-cost lexical similarity signal, not a security verdict.
        """
        import time
        t0 = time.perf_counter()
        
        z = self._embed_prompt(prompt)
        z_norm = float(np.linalg.norm(z))
        
        if z_norm < 1e-6:
            # Neutral / no matching keywords
            latency = (time.perf_counter() - t0) * 1000.0
            return JEPAResult(
                latent_energy=0.0,
                divergence_score=0.15,
                benign_affinity=0.10,
                adversarial_affinity=0.10,
                predicted_intent_class="BENIGN_ENTERPRISE",
                dominant_adversarial_concepts=[],
                dominant_benign_concepts=[],
                is_adversarial=False,
                latency_ms=round(latency, 3),
            )
            
        # Project onto both subspaces
        _, benign_energy = self.project(z, self.B_subspace)
        _, adv_energy = self.project(z, self.A_subspace)
        
        # Residual distances: distance to each hand-built anchor subspace
        # dist^2 = ||z||^2 - energy
        benign_dist_sq = max(0.0, 1.0 - benign_energy)
        adv_dist_sq = max(0.0, 1.0 - adv_energy)
        
        # Anchor score: positive when closer to adversarial than benign
        # E in [-1.0, +1.0]
        latent_energy = float(adv_energy - benign_energy)
        
        # Normalized divergence score in [0.0, 1.0]
        # High score means high risk of prompt injection / jailbreak
        if adv_energy > 0:
            divergence_score = adv_energy / (adv_energy + benign_energy + 1e-4)
        else:
            divergence_score = 0.0
            
        # Find dominant concepts
        tokens_lower = set(re.findall(r"\b[a-zA-Z]{3,}\b", prompt.lower()))
        adv_hits = [t for t in self.adv_vocab if t in tokens_lower]
        benign_hits = [t for t in self.benign_vocab if t in tokens_lower]
        
        # Intent classification
        has_attack_operator = any(op in tokens_lower for op in _ADV_OPERATORS) or (
            "system" in tokens_lower and "prompt" in tokens_lower
        )
        if not has_attack_operator:
            # Without an attack action verb/operator, prompt cannot be classified as adversarial injection
            if benign_energy >= 0.04:
                intent_class = "BENIGN_ENTERPRISE"
                is_adv = False
                divergence_score = min(0.20, divergence_score)
            else:
                intent_class = "AMBIGUOUS"
                is_adv = False
                divergence_score = min(0.30, divergence_score)
        elif (adv_energy >= 0.10 and divergence_score >= 0.55) or (adv_energy >= 0.20):
            intent_class = "ADVERSARIAL_INJECTION"
            is_adv = True
        elif (benign_energy >= 0.10 and divergence_score <= 0.25):
            intent_class = "BENIGN_ENTERPRISE"
            is_adv = False
        else:
            intent_class = "AMBIGUOUS"
            is_adv = (divergence_score >= 0.65)
            
        latency = (time.perf_counter() - t0) * 1000.0
        
        return JEPAResult(
            latent_energy=round(latent_energy, 4),
            divergence_score=round(float(divergence_score), 4),
            benign_affinity=round(float(min(1.0, benign_energy)), 4),
            adversarial_affinity=round(float(min(1.0, adv_energy)), 4),
            predicted_intent_class=intent_class,
            dominant_adversarial_concepts=list(dict.fromkeys(adv_hits))[:5],
            dominant_benign_concepts=list(dict.fromkeys(benign_hits))[:5],
            is_adversarial=is_adv,
            latency_ms=round(latency, 3),
        )


# Singleton
jepa_analyzer = JEPALatentAnalyzer()
