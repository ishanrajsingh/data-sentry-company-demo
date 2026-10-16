# Data Sentry

Data Sentry is an AI security gateway that checks prompts, retrieval, and model responses before information crosses a trust boundary. The project includes a local security dashboard and a separately deployable company assistant demo with authenticated roles and synthetic employee records.

## Try the hosted company demo

- **Web app:** [frontend-xi-lac-99.vercel.app](https://frontend-xi-lac-99.vercel.app)
- **API:** [data-sentry-company-demo-production.up.railway.app](https://data-sentry-company-demo-production.up.railway.app)
- **API health:** [/api/health](https://data-sentry-company-demo-production.up.railway.app/api/health)

The hosted app uses synthetic Northstar Systems data. Demo accounts and setup notes are listed in [`company_demo/README.md`](company_demo/README.md). Do not use it with real personal or company data.

## Screenshots

These previews are rendered from the deployed demo and API documentation.

| Company assistant | API reference |
| --- | --- |
| ![Northstar Systems sign-in screen](https://image.thum.io/get/width/1200/noanimate/https://frontend-xi-lac-99.vercel.app/) | ![Data Sentry API documentation](https://image.thum.io/get/width/1200/noanimate/https://data-sentry-company-demo-production.up.railway.app/docs) |

## Run the local gateway

Create a virtual environment and install the Python dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python scripts/setup_local.py
```

Start the API and React dashboard in separate terminals from the repository root:

```bash
PYTHON_BIN=.venv/bin/python ./run_api.sh
```

```bash
./run_ui.sh
```

Open `http://localhost:5173`. The dashboard proxies API calls to `http://127.0.0.1:8000`. The deterministic mock answer model is the default.

The optional semantic reviewer uses a local Ollama model (`qwen2.5:3b-instruct` by default):

```bash
ollama pull qwen2.5:3b-instruct
ollama serve
```

The reviewer receives a sanitized prompt and actor role, but no tools or retrieved documents. If it is unavailable or returns malformed output, the gateway holds the request. See `.env.example` for configuration.

## What it does

- Scans prompts for personal identifiers, payment data, credentials, and suspicious instructions.
- Applies configurable `warn`, `mask`, `block`, `redact`, and approval policies.
- Checks role, clearance, department, and document integrity before adding retrieved content to model context.
- Inspects generated output before returning it.
- Records privacy-aware audit events without storing full prompt or response text.
- Uses analyst feedback to adjust heuristic risk scores for similar requests. Feedback does not change hard DLP or document-access rules.
- Exposes a small MCP gateway with authenticated tool checks and non-destructive demo handlers.

## Architecture and limits

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the request flow and security boundaries. The repository also includes synthetic replay and curated pattern-coverage cases. Those results describe only the included corpus and are not independent security evaluations or guarantees. Semantic risk scores are heuristic rankings, not calibrated probabilities.

The local document store and selectable dashboard identities are for demonstration. The company assistant in `company_demo/` provides server-assigned demo roles and a MongoDB Atlas adapter for shared state. Both use synthetic data. The project is a prototype and is not intended to protect production systems.

## Project layout

- `app/`: FastAPI gateway, policy checks, DLP, retrieval, audit, and model adapters
- `ui/`: React dashboard for the local prototype
- `company_demo/`: isolated authenticated company assistant demo
- `config/policy.json`: configurable policy actions
- `scripts/`: local setup and evaluation helpers
- `tests/`: unit and integration tests
