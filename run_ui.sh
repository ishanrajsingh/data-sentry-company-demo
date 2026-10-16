#!/usr/bin/env bash
# Data Sentry: start the React UI (Vite dev server)
# Opens at http://localhost:5173 and proxies /api → http://127.0.0.1:8000

cd "$(dirname "$0")/ui" || exit 1
echo "Data Sentry React UI: http://localhost:5173"
echo "API proxy: http://127.0.0.1:8000 (make sure run_api.sh is running)"
echo ""
npm run dev
