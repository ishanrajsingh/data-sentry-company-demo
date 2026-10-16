#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -z "${PYTHON_BIN:-}" ]]; then
	if [[ -x .venv/bin/python ]]; then
		PYTHON_BIN=".venv/bin/python"
	else
		PYTHON_BIN="/usr/local/bin/python3"
	fi
fi
"$PYTHON_BIN" scripts/setup_local.py
exec "$PYTHON_BIN" -m uvicorn app.main:app --host "${INTENTLOCK_HOST:-127.0.0.1}" --port "${INTENTLOCK_PORT:-8000}"
