from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except ImportError:
    pass

from company_demo.backend.gateway import Gateway
from company_demo.backend.seed import ROLE_CLEARANCE, demo_credentials, seed_documents, seed_users
from company_demo.backend.security import (
    COOKIE_NAME,
    authenticate_password,
    create_session,
    public_user,
    request_user,
)
from company_demo.backend.store import MemoryStore, MongoStore


def build_store() -> Any:
    mongo_uri = os.getenv("MONGODB_URI", "").strip()
    hosted = bool(os.getenv("RAILWAY_ENVIRONMENT")) or os.getenv("DATA_SENTRY_ENV", "").casefold() == "production"
    if hosted:
        if not mongo_uri:
            raise RuntimeError("MONGODB_URI is required in hosted mode; refusing ephemeral audit storage.")
        for key in ("SESSION_SECRET", "AUDIT_HASH_SECRET"):
            value = os.getenv(key, "")
            if len(value) < 32 or value.startswith("replace-with-"):
                raise RuntimeError(f"{key} must be a strong deployment secret in hosted mode.")
    if mongo_uri:
        store = MongoStore(mongo_uri, os.getenv("MONGODB_DATABASE", "data_sentry_company_demo"))
    else:
        store = MemoryStore()
    store.initialize(seed_users(), seed_documents())
    return store


store = build_store()
gateway = Gateway(store)


@asynccontextmanager
async def lifespan(application: FastAPI):
    application.state.store = store
    application.state.gateway = gateway
    yield
    application.state.store.close()


app = FastAPI(
    title="Data Sentry Company Assistant",
    description="Synthetic Northstar Systems assistant behind an access-controlled AI security gateway.",
    version="1.0.0",
    lifespan=lifespan,
)

configured_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Requested-With"],
)


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=200)


class ChatBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=6000)


class FeedbackBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision_correct: bool


class MCPBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jsonrpc: str
    id: int | str | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


def _current_user(request: Request) -> dict[str, Any]:
    return request_user(request)


def _store(request: Request) -> Any:
    return request.app.state.store


def _gateway(request: Request) -> Gateway:
    return request.app.state.gateway


def _is_admin(user: dict[str, Any]) -> bool:
    return user.get("role") == "security_admin"


def _visible_event(event: dict[str, Any], user: dict[str, Any]) -> bool:
    return _is_admin(user) or event.get("user_id") == user.get("user_id")


@app.get("/api/health")
def health(request: Request) -> dict[str, Any]:
    active_gateway: Gateway = request.app.state.gateway
    active_store = request.app.state.store
    return {
        "ok": True,
        "company": "Northstar Systems",
        "storage": active_store.backend_name,
        "answer_model": os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"),
        "groq_configured": bool(active_gateway.groq_api_key),
        "synthetic_data": True,
    }


@app.get("/api/demo-accounts")
def get_demo_accounts() -> dict[str, Any]:
    if os.getenv("ALLOW_DEMO_CREDENTIALS", "true").casefold() not in {"1", "true", "yes"}:
        raise HTTPException(status_code=404, detail="Demo accounts are disabled.")
    return {"accounts": demo_credentials(), "synthetic_only": True}


@app.post("/api/auth/login")
def login(body: LoginBody, response: Response, request: Request) -> dict[str, Any]:
    email = body.email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    user = request.app.state.store.find_user(email)
    if not authenticate_password(user, body.password):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    secure_cookie = os.getenv("SESSION_COOKIE_SECURE", "false").casefold() in {"1", "true", "yes"}
    same_site = os.getenv("SESSION_COOKIE_SAMESITE", "lax").casefold()
    if same_site not in {"lax", "strict", "none"}:
        same_site = "lax"
    response.set_cookie(
        key=COOKIE_NAME,
        value=create_session(user),
        max_age=8 * 60 * 60,
        httponly=True,
        secure=secure_cookie,
        samesite=same_site,
        path="/",
    )
    return {"user": public_user(user)}


@app.post("/api/auth/logout")
def logout(response: Response) -> dict[str, bool]:
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: dict[str, Any] = Depends(_current_user)) -> dict[str, Any]:
    return {"user": public_user(user)}


@app.post("/api/chat")
def chat(
    body: ChatBody,
    request: Request,
    user: dict[str, Any] = Depends(_current_user),
) -> dict[str, Any]:
    return request.app.state.gateway.chat(body.prompt, user)


@app.get("/api/documents")
def documents(
    request: Request,
    user: dict[str, Any] = Depends(_current_user),
) -> dict[str, Any]:
    active_gateway: Gateway = request.app.state.gateway
    visible = [
        {
            "document_id": item["document_id"],
            "title": item["title"],
            "classification": item["classification"],
            "topics": item.get("topics", []),
        }
        for item in request.app.state.store.list_documents()
        if active_gateway._authorized(item, user) and not active_gateway._document_has_injection(item)
    ]
    return {"documents": visible}


@app.get("/api/audit")
def audit_list(
    request: Request,
    user: dict[str, Any] = Depends(_current_user),
    decision: str | None = Query(default=None, max_length=16),
    role: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, ge=1, le=100),
) -> dict[str, Any]:
    if role and not _is_admin(user):
        raise HTTPException(status_code=403, detail="Only security admins can filter by user role.")
    events = request.app.state.store.list_events(None if _is_admin(user) else user["user_id"], limit=limit)
    if decision:
        events = [event for event in events if event.get("decision", "").casefold() == decision.casefold()]
    if role:
        events = [event for event in events if event.get("role", "").casefold() == role.casefold()]
    return {"events": events, "scope": "company" if _is_admin(user) else "own"}


@app.get("/api/audit/{event_id}")
def audit_detail(
    event_id: str,
    request: Request,
    user: dict[str, Any] = Depends(_current_user),
) -> dict[str, Any]:
    event = request.app.state.store.get_event(event_id)
    if not event or not _visible_event(event, user):
        raise HTTPException(status_code=404, detail="Audit event was not found.")
    return {"event": event}


@app.post("/api/audit/{event_id}/feedback")
def submit_feedback(
    event_id: str,
    body: FeedbackBody,
    request: Request,
    user: dict[str, Any] = Depends(_current_user),
) -> dict[str, Any]:
    active_store = request.app.state.store
    event = active_store.get_event(event_id)
    if not event or not _visible_event(event, user):
        raise HTTPException(status_code=404, detail="Audit event was not found.")
    feedback = {
        "event_id": event_id,
        "user_id": user["user_id"],
        "role": event["role"],
        "profile_key": event.get("profile_key", ""),
        "decision_correct": body.decision_correct,
        "original_decision": event.get("decision", "ALLOW"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if not active_store.add_feedback(feedback):
        raise HTTPException(status_code=409, detail="Feedback has already been recorded for this event.")
    return {
        "ok": True,
        "decision_correct": body.decision_correct,
        "message": "Feedback saved and added to the role-scoped learning profile.",
    }


@app.get("/api/summary")
def summary(
    request: Request,
    user: dict[str, Any] = Depends(_current_user),
) -> dict[str, Any]:
    events = request.app.state.store.list_events(None if _is_admin(user) else user["user_id"], limit=100)
    decisions = {name: sum(1 for item in events if item.get("decision") == name) for name in ("ALLOW", "WARN", "BLOCK")}
    categories: dict[str, int] = {}
    for event in events:
        for category in event.get("dlp_categories", []):
            categories[category] = categories.get(category, 0) + 1
    return {
        "event_count": len(events),
        "decisions": decisions,
        "categories": categories,
        "scope": "company" if _is_admin(user) else "own",
        "recent_events": events[:6],
    }


@app.post("/api/mcp")
def mcp(
    body: MCPBody,
    request: Request,
    user: dict[str, Any] = Depends(_current_user),
) -> dict[str, Any]:
    if body.jsonrpc != "2.0":
        raise HTTPException(status_code=400, detail="MCP requests must use JSON-RPC 2.0.")
    if body.method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": body.id,
            "result": {
                "tools": [
                    {
                        "name": "search_documents",
                        "description": "Search company documents visible to the signed-in account.",
                        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"], "additionalProperties": False},
                    },
                    {
                        "name": "read_document",
                        "description": "Read one company document after role and clearance checks.",
                        "inputSchema": {"type": "object", "properties": {"document_id": {"type": "string"}}, "required": ["document_id"], "additionalProperties": False},
                    },
                ]
            },
        }
    if body.method != "tools/call":
        return {"jsonrpc": "2.0", "id": body.id, "error": {"code": -32601, "message": "Method not found."}}
    params = body.params
    tool_name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(tool_name, str) or not isinstance(arguments, dict):
        raise HTTPException(status_code=422, detail="MCP tool name and arguments are required.")
    result = request.app.state.gateway.execute_tool(tool_name, arguments, user)
    is_error = result["decision"] != "ALLOW"
    return {
        "jsonrpc": "2.0",
        "id": body.id,
        "result": {
            "isError": is_error,
            "content": [{"type": "text", "text": result["reason"] if is_error else str(result["result"])}],
            "security": {
                "decision": result["decision"],
                "reason": result["reason"],
                "denied_document_count": result["denied_document_count"],
                "event_id": result["event_id"],
            },
        },
    }
