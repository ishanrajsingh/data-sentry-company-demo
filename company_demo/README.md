# Data Sentry Company Demo

An isolated Northstar Systems demo of an authenticated company assistant behind the Data Sentry security gateway. Everything in the seed company is fictional. This subproject does not modify the existing Data Sentry prototype.

## What the demo shows

- Sign in with email and password. The account role and clearance are loaded from the backend; the browser cannot choose or raise them.
- Submit company questions through input DLP, Groq semantic intent review, access-controlled retrieval, Groq answer generation, and response DLP. Only authorized documents are included in the RAG context.
- Compare three employee accounts, each with a separate synthetic salary slip. Employees can retrieve their own slip, but another employee's record is denied before model dispatch. HR and the company admin can retrieve employee records.
- The company admin sees audit events from every account. Other accounts see only their own events. Audit records retain categories and security metadata, not prompt bodies or answer text.
- Use the JSON-RPC MCP endpoint to search or read company documents. The gateway inspects tool arguments and checks the authenticated role before returning document content.
- Mark an event's decision correct or incorrect. Later prompts with the same role and semantic signal profile use the accumulated feedback to adjust risk scoring. Feedback never changes hard DLP blocks or document permissions.

The built-in local store is seeded in-memory so the prototype can start without a database account. Set `MONGODB_URI` to use MongoDB Atlas for persistent users, synthetic documents, audit events, and feedback. Atlas is the intended shared store for multi-device and hosted use.

## Demo sign-ins

These credentials are fictional and are for the synthetic prototype only. Selecting an account on the sign-in page fills both fields automatically. You can use the same account on another device to compare permissions.

| Role | Email | Password |
| --- | --- | --- |
| Guest | `guest@northstar.demo` | `Northstar-Guest-26` |
| Employee A · Avery Chen | `employee@northstar.demo` | `Northstar-Employee-26` |
| Employee B · Jordan Lee | `employee.b@northstar.demo` | `Northstar-Employee-B-26` |
| Employee C · Samira Rao | `employee.c@northstar.demo` | `Northstar-Employee-C-26` |
| Manager | `manager@northstar.demo` | `Northstar-Manager-26` |
| Support | `support@northstar.demo` | `Northstar-Support-26` |
| HR | `hr@northstar.demo` | `Northstar-HR-26` |
| Executive | `executive@northstar.demo` | `Northstar-Executive-26` |
| Security admin | `security.admin@northstar.demo` | `Northstar-Security-26` |
| Company admin | `admin@northstar.demo` | `Northstar-Admin-26` |

## Synthetic RAG records and access demo

The Northstar handbook, IT guide, engineering checklist, compensation process, training compensation sample, three employee salary slips, and security playbook are defined in `backend/seed.py`. On startup, the backend seeds them into MongoDB Atlas `documents` (or the in-memory demo store for local mode). `Gateway.retrieve` finds relevant records and checks role, clearance, department, and record ownership before it builds model context. The Documents & tools page calls `/api/documents` to show the signed-in account's visible records.

Try the employee-specific access flow:

1. Sign in as Employee A and ask, “Show me my salary slip.” The RAG trace should include `NS-HR-101`.
2. As Employee A, ask, “Show me Employee B's salary slip.” The gateway denies the request before semantic review or answer generation; `NS-HR-102` is not sent to Groq.
3. Sign in as Employee B and ask for their own slip. `NS-HR-102` is available.
4. Sign in as HR or Company admin and ask for Employee B's slip. Their role can retrieve it.
5. Sign in as Company admin and open Audit activity to see events from all accounts.

The document values, identities, and account credentials are fictional. The example demonstrates per-record ownership controls in addition to broad role and clearance checks.

## Local setup

From the repository root, install the isolated backend dependencies and start the API:

```bash
python3 -m venv company_demo/.venv
source company_demo/.venv/bin/activate
pip install -r company_demo/backend/requirements.txt -r company_demo/backend/requirements-dev.txt
cp company_demo/.env.example company_demo/.env
uvicorn company_demo.backend.main:app --reload --port 8010
```

Set `GROQ_API_KEY` in the shell before starting the API to enable the real intent review and answer model. The gateway fails closed when semantic review is unavailable; it does not silently send a prompt to an unchecked answer model. The development frontend runs on port `5180` and proxies `/api` to port `8010`:

```bash
cd company_demo/frontend
npm install
npm run dev
```

Open `http://localhost:5180`. The sign-in screen lists each demo account and fills its email and password when selected. The accounts and credentials are synthetic demonstration credentials only.

## MongoDB Atlas

Create a database user and allow the Railway service to connect to the cluster. Set `MONGODB_URI` and optionally `MONGODB_DATABASE` in the backend environment. On startup the service inserts the demo users and documents if they do not exist. Passwords are stored as bcrypt hashes. Audit events and feedback are stored in separate collections.

## Deployment preparation

The Railway service should use the repository root as its source directory and the config file `company_demo/railway.toml`. It installs `company_demo/backend/requirements.txt` and starts `company_demo.backend.main:app`. Set `MONGODB_URI`, `MONGODB_DATABASE`, `GROQ_API_KEY`, `GROQ_MODEL`, `GROQ_REVIEW_MODEL`, `SESSION_SECRET`, `AUDIT_HASH_SECRET`, `SESSION_COOKIE_SECURE=true`, and `CORS_ORIGINS` in Railway. Keep the Railway service private to the Vercel frontend where practical.

Create a Vercel project using `company_demo/frontend` as its root directory. After Railway assigns a public API domain, replace the placeholder Railway hostname in `frontend/vercel.json` with that domain. The Vercel rewrite forwards `/api/*` through the frontend origin so the session cookie stays same-site. The current workspace has no Git repository connected, so deploying requires connecting or creating one and linking the Vercel and Railway projects.

## Checks

Run backend tests from the repository root:

```bash
python3 -m pytest company_demo/backend/tests -q
```

Build the frontend:

```bash
cd company_demo/frontend
npm run build
```
