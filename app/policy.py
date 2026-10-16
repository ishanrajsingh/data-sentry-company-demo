import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


DEFAULT_POLICY: Dict[str, str] = {
    # Empty identity fields and first-person account maintenance are warnings,
    # not evidence of disclosure or an extraction attempt.
    "empty_aadhaar_field": "warn",
    "empty_pan_field": "warn",
    "personal_financial_update": "warn",
    # Sensitive employee records are removed from the submitted text.
    "date_of_birth": "redact",
    "postal_address": "redact",
    "bank_account": "redact",
    "medical_record": "redact",
    "employee_id": "redact",
    # Explicitly labeled personal identity fields — mask before model dispatch
    "person_name": "mask",
    # Government-issued identity numbers — BLOCK: exposure enables identity fraud
    "pan": "block",
    "aadhar": "block",
    # Contact identifiers — mask (low-risk individually)
    "phone": "mask",
    "email": "mask",
    # Credentials — always BLOCK
    "api_key": "block",
    "password": "block",
    "secret": "block",
    "private_key": "block",
    "credit_card": "block",
    "upi": "block",
    "ifsc": "block",
    # Security controls
    "prompt_injection": "block",
    "canary": "block",
    "markdown_exfil": "redact",
    "threat_intelligence": "block",
    "sensitive_context_extraction": "block",
}

POLICY_ACTIONS = frozenset({"warn", "mask", "block", "redact", "require_approval"})


@dataclass
class Policy:
    rules: Dict[str, str] = field(default_factory=lambda: DEFAULT_POLICY.copy())

    def __post_init__(self) -> None:
        invalid = {
            str(action) for action in self.rules.values()
            if not isinstance(action, str) or action not in POLICY_ACTIONS
        }
        if invalid:
            raise ValueError(f"Unsupported policy action(s): {', '.join(sorted(invalid))}")

    def decide(self, category: str) -> str:
        return self.rules.get(category, "warn")

    def should_block(self, findings: List[str]) -> bool:
        return any(self.rules.get(item, "warn") == "block" for item in findings)

    def compile_matrix(self) -> Dict[str, object]:
        return {
            "input_rules": {
                key: {"action": value} for key, value in self.rules.items()
            },
            "output_rules": {
                key: {"action": value} for key, value in self.rules.items()
            },
            "metadata": {
                "audit_raw_content": False,
                "conditional_rules": [
                    {"category": "pan", "condition": "No nearby PAN context", "action": "warn"},
                    {"category": "aadhar", "condition": "No nearby Aadhaar context", "action": "warn"},
                    {"category": "phone", "condition": "No country prefix or phone context", "action": "warn"},
                    {"category": "unmatched_finding", "condition": "No explicit category rule", "action": "warn"},
                ],
            },
        }


def build_default_policy() -> Policy:
    rules = DEFAULT_POLICY.copy()
    configured_path = os.environ.get("INTENTLOCK_POLICY_FILE")
    path = Path(configured_path) if configured_path else Path(__file__).resolve().parents[1] / "config" / "policy.json"
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Policy configuration must be a JSON object")
        overrides = data.get("rules", data)
        if not isinstance(overrides, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in overrides.items()
        ):
            raise ValueError("Policy configuration must be a JSON object of category-to-action rules")
        rules.update(overrides)
    return Policy(rules=rules)
