# Data Sentry architecture

Data Sentry is an AI security gateway prototype. Its core security story is enforcement at the input, retrieval, and response boundaries. The model is treated as an untrusted processor, not as the authority for document permissions.

## Request path

1. Authenticated routes resolve role, clearance, and department from the server-side bearer-token registry. Client role fields do not override that identity.
2. Prompt text is normalized and scanned for personal identifiers, payment data, credentials, and prompt-injection patterns. Policy actions determine whether a request is allowed, sanitized, or blocked.
3. The in-memory knowledge base selects relevant documents and checks document integrity, role, clearance, and department before context is assembled.
4. The sanitized prompt, actor role, and (only when true) a positive RAG-authorization flag go to a loopback Ollama classifier. It evaluates semantic intent without access to tools, retrieved documents, or remote providers. The app warms the model before reporting startup complete. Malformed output or service failure is held closed. This model review is probabilistic, not a guarantee.
5. Approved input and authorized context go to the selected answer model adapter. The deterministic mock is the local default; a hosted Groq answer adapter is optional.
6. The buffered response is inspected for sensitive patterns and restricted canary markers before it is returned. Provider errors fail closed.
7. The audit ledger records category, action, source, rule, role, outcome, safe reference, and keyed fingerprints. It does not store raw prompt or response text.

## Interactive prototype behavior

- `POST /analyze/trace` is loopback-only and evaluates an editable prompt without forwarding it to the answer model. Eligible sanitized prompts go to the isolated local semantic classifier. It also runs input checks, heuristic risk scoring, the same in-memory document permission check, jailbreak pattern screening, and adaptive scoring. It stores a keyed prompt fingerprint and writes a privacy-safe audit event.
- The prototype accepts analyst labels after each trace. Correct and corrected labels adjust the associated signal's future score, with larger adjustments for corrections. Exact prompt memory is scoped by role, clearance, and department; two false-positive reports for the same scoped prompt activate prompt-specific memory. Feedback can adjust heuristic risk scores, but mandatory DLP, jailbreak, and retrieval blocks remain in force. Corpus evaluation explicitly skips learning so synthetic benchmark runs do not contaminate feedback history.
- The MCP demo checks both tool-level permissions and sensitive resource names in reference document/database calls. These are illustrative allowlists for stub tools, not a general-purpose filesystem or SQL policy engine.
- The indirect-injection scenario offers both a direct override and a harmless-looking query for a synthetic imported bulletin containing a malicious instruction. The retrieval layer detects and quarantines the injected document before context assembly.
- The trace accepts a simulated role for the loopback demo. Authenticated API routes resolve role and clearance server-side. The project remains a prototype with an in-memory synthetic document store.
- `GET /demo/metrics` evaluates the included synthetic corpus and returns aggregate, development, and holdout metrics. The baseline comparisons are counterfactual simulations.
- `GET /audit/events` returns recent metadata-only events and is loopback-only.
- `POST /demo/feedback`, `GET /demo/learning`: loopback-only analyst feedback and learning status for the local dashboard. Authenticated API clients use `POST /feedback` and `GET /learning/stats`.
- `POST /mcp`, `POST /mcp/inspect`: authenticated MCP JSON-RPC calls and pre-dispatch inspection use the server-side principal. `POST /demo/mcp*` uses simulated roles on loopback only. All built-in handlers are non-destructive stubs.
- `GET /mcp/tools`: registered tool catalog; it contains no user data.

## Semantic reviewer

The local Qwen 2.5 3B reviewer stays in the prototype because it can reason about request intent and authorized work, while the deterministic retrieval gate makes the actual role/clearance decision. A replay of 46 synthetic prompts produced no decision mismatches or reviewer errors with the configured 12-second request cap; this is a prototype corpus result, not a general accuracy claim.

Meta Prompt Guard 2 (22M/86M) is a promising faster companion for explicit instruction-override and jailbreak detection. Its stated scope is whether a prompt tries to supersede prior instructions, and its model card documents a 512-token context; it does not replace the RAG authorization gate or broader private-data intent review. ProtectAI LLM Guard also offers a DeBERTa prompt-injection scanner, with its docs describing the detector as still under testing. We did not add either dependency to this prototype: a smaller Qwen 1.5B replay was quicker but falsely blocked authorized HR and benign security-education prompts, while the 3B model passed the project replay. Candidate repositories: [Meta PurpleLlama Prompt Guard 2](https://github.com/meta-llama/PurpleLlama/tree/main/Llama-Prompt-Guard-2), [ProtectAI LLM Guard scanner](https://github.com/protectai/llm-guard/blob/main/docs/input_scanners/prompt_injection.md), and [Prompt Armor](https://github.com/prompt-armor/prompt-armor). Third-party headline benchmarks were not treated as directly comparable to Data Sentry's test set.
- `GET /demo/metrics`, `GET /scenarios`, `POST /demo/{scenario}`: loopback-only prototype helpers.

## Main modules

| Module | Responsibility |
| --- | --- |
| `app/main.py` | FastAPI routes, request orchestration, pre-model trace, evaluation summaries |
| `app/dlp.py`, `app/normalizer.py`, `app/policy.py` | Text normalization, sensitive-content checks, policy actions |
| `app/threat_intelligence.py`, `app/jepa_analyzer.py`, `app/jeb_defense.py` | Heuristic risk scoring, lexical concept-anchor projection, and curated jailbreak patterns |
| `app/rag.py` | Synthetic documents, relevance selection, integrity screening, role and clearance authorization |
| `app/model_adapter.py` | Local deterministic mock and optional hosted model adapter |
| `app/semantic_review.py` | Loopback-only probabilistic intent classifier with fail-closed handling |
| `app/audit.py` | SQLite audit ledger with HMAC fingerprints and row-chain integrity checks |
| `app/benchmark.py` | Curated synthetic evaluation corpus |
| `ui/src` | React dashboard, prototype scenarios, architecture overview, and audit log |

## Endpoint summary

- `GET /health`: gateway liveness and local capability counts.
- `POST /scan`: authenticated input scan.
- `POST /ask`: authenticated gateway request with server-resolved identity.
- `POST /v1/chat/completions`: authenticated, non-streaming OpenAI-compatible route.
- `POST /analyze/trace`: local prototype trace; may dispatch to the isolated local classifier, never to the answer model.
- `GET /demo/metrics`: local synthetic corpus evaluation summary.
- `GET /audit/events`: recent metadata-only audit events for the local dashboard.
- `GET /replay`, `GET /metrics`: authenticated evaluation summaries.
- `GET /jeb/benchmark`, `POST /jepa/analyze`: focused detector analysis endpoints.

## Evaluation limits

The included corpus contains 100 curated synthetic cases: 25 legitimate requests, 20 sensitive-input cases, 20 direct-injection cases, 15 indirect-injection cases, and 20 unauthorized-retrieval cases. It is split into development and in-repository holdout subsets. The holdout is not an independent external evaluation. Detection metrics describe this corpus and must not be presented as general real-world accuracy claims. The risk score is an uncalibrated heuristic ranking, not a probability. The lexical concept-anchor component uses hand-built token vocabularies; it is not JEPA or a learned semantic embedding model. The JEB route reports coverage on curated scanner cases, not end-to-end attack resilience.

The replay baselines simulate missing controls against the same cases. They are not separate runs against unprotected models. The included corpus evaluation disables the semantic model for deterministic, fast, repeatable measurements; it therefore does not measure novel paraphrase detection. Semantic classification is probabilistic and can still miss or over-block requests. The RAG store is in-memory and synthetic. The React dashboard's selectable identity is for demonstration only.

## Operational boundaries

- The launch scripts bind to loopback by default. Keep the prototype on a trusted local machine.
- Use synthetic identifiers and credentials only.
- Provider keys, bootstrap bearer tokens, and the audit HMAC key must remain local and out of screenshots or source control.
- Streaming model responses are not supported because output must be inspected before delivery.
- Audit retention, multi-worker session persistence, external holdout validation, and production document indexing remain future work.
