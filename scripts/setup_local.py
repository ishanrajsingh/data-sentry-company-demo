from __future__ import annotations

import json
import argparse
import secrets
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"


def rotate_local_credentials(env_path: Path, clear_groq_key: bool = False) -> None:
    lines = env_path.read_text(encoding="utf-8").splitlines()
    updated_lines = []
    rotated_api_keys = False
    rotated_dashboard_password = False
    for line in lines:
        if line.startswith("INTENTLOCK_API_KEYS="):
            raw_value = line.split("=", 1)[1].strip().strip("'\"")
            old_registry = json.loads(raw_value)
            new_registry = {
                secrets.token_urlsafe(32): attributes
                for attributes in old_registry.values()
                if isinstance(attributes, dict)
            }
            updated_lines.append(f"INTENTLOCK_API_KEYS='{json.dumps(new_registry, separators=(',', ':'))}'")
            rotated_api_keys = True
        elif line.startswith("INTENTLOCK_DASHBOARD_PASSWORD="):
            updated_lines.append(f"INTENTLOCK_DASHBOARD_PASSWORD={secrets.token_urlsafe(24)}")
            rotated_dashboard_password = True
        elif clear_groq_key and line.startswith("GROQ_API_KEY="):
            updated_lines.append("GROQ_API_KEY=")
        else:
            updated_lines.append(line)

    env_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
    try:
        env_path.chmod(0o600)
    except OSError:
        pass
    print(
        f"Rotated local API tokens: {rotated_api_keys}; "
        f"dashboard passphrase: {rotated_dashboard_password}; "
        f"cleared exposed Groq key: {clear_groq_key}."
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rotate-local-credentials", action="store_true")
    parser.add_argument("--clear-groq-key", action="store_true")
    args = parser.parse_args()

    if args.rotate_local_credentials:
        if not ENV_FILE.exists():
            raise SystemExit(".env does not exist; run setup_local.py first.")
        rotate_local_credentials(ENV_FILE, clear_groq_key=args.clear_groq_key)
        return

    if ENV_FILE.exists():
        existing = ENV_FILE.read_text(encoding="utf-8")
        additions = []
        if "INTENTLOCK_DASHBOARD_PASSWORD=" not in existing:
            additions.append(f"INTENTLOCK_DASHBOARD_PASSWORD={secrets.token_urlsafe(24)}")
        if "INTENTLOCK_USERS_DB=" not in existing:
            additions.append("INTENTLOCK_USERS_DB=data/users.db")
        if "INTENTLOCK_AUDIT_DB=" not in existing:
            additions.append("INTENTLOCK_AUDIT_DB=data/audit_events_v2.db")
        if additions:
            with ENV_FILE.open("a", encoding="utf-8") as env_file:
                env_file.write("\n" + "\n".join(additions) + "\n")
            try:
                ENV_FILE.chmod(0o600)
            except OSError:
                pass
            print("Added missing local security settings to .env.")
        else:
            print("Local .env already has the required settings; leaving it unchanged.")
        return

    users = {
        secrets.token_urlsafe(32): {
            "name": "employee-demo",
            "role": "employee",
            "clearance": "INTERNAL",
            "department": "Support",
        },
        secrets.token_urlsafe(32): {
            "name": "hr-demo",
            "role": "hr",
            "clearance": "RESTRICTED",
            "department": "People_Operations",
        },
    }
    contents = "\n".join(
        [
            f"INTENTLOCK_API_KEYS='{json.dumps(users, separators=(',', ':'))}'",
            "INTENTLOCK_MODEL_BACKEND=mock",
            "GROQ_API_KEY=",
            f"INTENTLOCK_DASHBOARD_PASSWORD={secrets.token_urlsafe(24)}",
            "INTENTLOCK_USERS_DB=data/users.db",
            "INTENTLOCK_AUDIT_DB=data/audit_events.db",
            "",
        ]
    )
    ENV_FILE.write_text(contents, encoding="utf-8")
    try:
        ENV_FILE.chmod(0o600)
    except OSError:
        pass
    print("Created loopback-only local .env with random demo bearer keys.")
    print("Read the generated keys from .env to call the authenticated API.")


if __name__ == "__main__":
    main()