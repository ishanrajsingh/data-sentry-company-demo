"""MCP JSON-RPC gateway with role checks and tool-argument inspection.

The prototype checks registered tool calls before dispatch. It applies role
permissions, sensitive-data scanning, and basic command, path, and SQL checks.
Built-in handlers are demonstration stubs; this is not a general-purpose MCP
proxy or a substitute for application-specific authorization.
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import unquote
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.dlp import apply_action_to_text, scan_text
from app.jepa_analyzer import jepa_analyzer
from app.jeb_defense import jeb_engine
from app.policy import DEFAULT_POLICY


# ── High-Risk Command & Path Traversal Patterns ──────────────────────────────
_DANGEROUS_SHELL_COMMANDS = re.compile(
    r"\b(rm\s+-rf|mkfs|dd\s+if=|chmod\s+777|chown|shutdown|reboot|"
    r"curl\s+[^>\n|]*\|(\s*bash|\s*sh)|wget\s+[^>\n|]*\|(\s*bash|\s*sh)|"
    r"nc\s+-[el]|bash\s+-i|/dev/tcp/|cat\s+/etc/shadow|cat\s+/etc/passwd|"
    r"powershell\s+-enc|cmd\.exe\s+/c|net\s+user\s+/add)\b",
    re.IGNORECASE,
)

_PATH_TRAVERSAL = re.compile(
    r"((?:^|[/\\])\.\.(?:[/\\]|$)|/etc/passwd|/etc/shadow|\.env|id_rsa|\.aws/credentials|\.kube/config)",
    re.IGNORECASE,
)

_SQL_INJECTION = re.compile(
    r"(\bDROP\s+TABLE\b|\bUNION\s+ALL\s+SELECT\b|\bOR\s+1\s*=\s*1\b|;\s*DELETE\s+FROM|;\s*UPDATE\b.*SET)",
    re.IGNORECASE,
)


@dataclass
class MCPToolDefinition:
    """Definition of an MCP Tool with security metadata and authorization tier."""
    name: str
    description: str
    input_schema: Dict[str, Any]
    required_role: str = "employee"        # employee | developer | hr | admin
    required_clearance: str = "PUBLIC"     # PUBLIC | INTERNAL | RESTRICTED | TOP_SECRET
    category: str = "general"              # filesystem | system | database | communication | intelligence
    is_dangerous: bool = False             # Requires explicit confirmation / admin role


@dataclass
class MCPToolInspectionResult:
    """Security audit result for an intercepted MCP tool call."""
    allowed: bool
    tool_name: str
    decision: str                          # "ALLOW" | "MASK_AND_ALLOW" | "BLOCK"
    reason: str
    violations: List[str]
    sanitized_arguments: Dict[str, Any]
    latency_ms: float
    owasp_mcp_risk: str = "LLM02 — Insecure Tool Execution"


class MCPGateway:
    """
    Model Context Protocol (MCP) Security Gateway & Interceptor.
    """

    def __init__(self):
        self._tools: Dict[str, MCPToolDefinition] = {}
        self._handlers: Dict[str, Callable[[Dict[str, Any]], Any]] = {}
        self._audit_log: List[Dict[str, Any]] = []
        self._register_default_tools()

    def _register_default_tools(self):
        """Register reference enterprise MCP tools for demonstration and proxying."""
        self.register_tool(
            MCPToolDefinition(
                name="read_document",
                description="Read internal documentation from authorized knowledge base.",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
                required_role="employee",
                required_clearance="INTERNAL",
                category="filesystem",
            ),
            handler=lambda args: f"Document contents for: {args.get('path')}",
        )
        self.register_tool(
            MCPToolDefinition(
                name="query_database",
                description="Query enterprise database for business metrics and reports.",
                input_schema={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
                required_role="developer",
                required_clearance="RESTRICTED",
                category="database",
            ),
            handler=lambda args: f"Executed query: {args.get('query')}",
        )
        self.register_tool(
            MCPToolDefinition(
                name="execute_system_command",
                description="Execute system maintenance command in sandboxed environment.",
                input_schema={
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
                required_role="admin",
                required_clearance="TOP_SECRET",
                is_dangerous=True,
                category="system",
            ),
            handler=lambda args: f"Executed command: {args.get('command')}",
        )
        self.register_tool(
            MCPToolDefinition(
                name="send_employee_notification",
                description="Send Slack or email notification to an employee.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "recipient": {"type": "string"},
                        "message": {"type": "string"},
                    },
                    "required": ["recipient", "message"],
                },
                required_role="employee",
                required_clearance="PUBLIC",
                category="communication",
            ),
            handler=lambda args: f"Notification sent to {args.get('recipient')}",
        )

    def register_tool(
        self,
        tool: MCPToolDefinition,
        handler: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ):
        """Register an MCP tool into the gateway."""
        self._tools[tool.name] = tool
        if handler:
            self._handlers[tool.name] = handler

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return MCP-compliant list of tools."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
                "security": {
                    "required_role": t.required_role,
                    "required_clearance": t.required_clearance,
                    "category": t.category,
                    "is_dangerous": t.is_dangerous,
                },
            }
            for t in self._tools.values()
        ]

    @staticmethod
    def role_clearance(role: str) -> str:
        return {
            "guest": "PUBLIC",
            "employee": "INTERNAL",
            "support": "INTERNAL",
            "manager": "CONFIDENTIAL",
            "developer": "RESTRICTED",
            "hr": "RESTRICTED",
            "executive": "TOP_SECRET",
            "security_admin": "TOP_SECRET",
            "admin": "TOP_SECRET",
        }.get(role.lower(), "PUBLIC")

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_role: str = "employee",
        user_clearance: str = "PUBLIC",
    ) -> MCPToolInspectionResult:
        """
        Deep security inspection of an MCP tool invocation.
        Runs DLP, lexical-anchor, path-traversal, and command-injection checks on arguments.
        """
        t0 = time.perf_counter()
        violations: List[str] = []
        try:
            sanitized_args = json.loads(json.dumps(arguments))  # JSON-safe deep copy
        except (TypeError, ValueError):
            sanitized_args = {}
            violations.append("Arguments are not valid JSON data.")
            return MCPToolInspectionResult(
                allowed=False, tool_name=tool_name, decision="BLOCK",
                reason=violations[-1], violations=violations,
                sanitized_arguments=sanitized_args,
                latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )
        decision = "ALLOW"
        allowed = True

        # 1. Unknown Tool Check
        if tool_name not in self._tools:
            violations.append(f"Attempted to invoke unregistered MCP tool: '{tool_name}'")
            latency = (time.perf_counter() - t0) * 1000.0
            return MCPToolInspectionResult(
                allowed=False,
                tool_name=tool_name,
                decision="BLOCK",
                reason=f"Tool '{tool_name}' is not registered in MCP catalog.",
                violations=violations,
                sanitized_arguments=sanitized_args,
                latency_ms=round(latency, 3),
            )

        tool_def = self._tools[tool_name]

        # 2. Role-Based Access Control (RBAC) Enforcement
        ROLE_HIERARCHY = {
            "guest": 0, "employee": 1, "support": 1, "manager": 2,
            "hr": 3, "developer": 3, "admin": 4, "executive": 4,
            "security_admin": 4,
        }
        user_level = ROLE_HIERARCHY.get(user_role.lower(), 1)
        req_level = ROLE_HIERARCHY.get(tool_def.required_role.lower(), 1)

        if user_level < req_level:
            violations.append("RBAC Violation: tool is not permitted for the authenticated role.")
            decision = "BLOCK"
            allowed = False

        CLEARANCE_LEVELS = {
            "PUBLIC": 1, "INTERNAL": 2, "CONFIDENTIAL": 3,
            "RESTRICTED": 4, "TOP_SECRET": 5,
        }
        effective_clearance = (user_clearance or self.role_clearance(user_role)).upper()
        user_clearance_level = CLEARANCE_LEVELS.get(effective_clearance, 0)
        required_clearance_level = CLEARANCE_LEVELS.get(tool_def.required_clearance.upper(), 5)
        if user_clearance_level < required_clearance_level:
            violations.append("Clearance Violation: tool is not permitted for the authenticated clearance.")
            decision = "BLOCK"
            allowed = False

        # 3. Argument Parameter Inspection
        def collect_strings(value: Any) -> List[str]:
            if isinstance(value, str):
                return [value]
            if isinstance(value, dict):
                return [part for item in value.values() for part in collect_strings(item)]
            if isinstance(value, (list, tuple)):
                return [part for item in value for part in collect_strings(item)]
            return []

        arg_string = " ".join(collect_strings(arguments))
        decoded_arg_string = unquote(arg_string).replace("\\", "/")

        # Reference tools can target documents or tables more sensitive than
        # their broad tool-level role. Enforce that resource boundary here too.
        resource_text = decoded_arg_string.casefold()
        hr_clearance = user_clearance_level >= CLEARANCE_LEVELS["RESTRICTED"]
        if tool_name == "read_document" and re.search(
            r"(?:^|[/_ -])(?:salary|compensation|payroll|employee[_ -]?records?)(?:[/_. -]|$)",
            resource_text,
        ):
            if user_role.casefold() != "hr" or not hr_clearance:
                violations.append("Resource access denied by HR role and RESTRICTED clearance policy.")
                decision = "BLOCK"
                allowed = False
        if tool_name == "query_database":
            requests_hr_data = bool(re.search(
                r"\b(?:salary|compensation|payroll|employee_records?|hr_records?)\b",
                resource_text,
            ))
            requests_secrets = bool(re.search(
                r"\b(?:credentials?|api_keys?|passwords?|secrets?)\b",
                resource_text,
            ))
            if requests_hr_data and (user_role.casefold() != "hr" or not hr_clearance):
                violations.append("Database resource denied by HR role and RESTRICTED clearance policy.")
                decision = "BLOCK"
                allowed = False
            if requests_secrets and user_role.casefold() not in {"admin", "security_admin"}:
                violations.append("Credential resources are restricted to security administrators.")
                decision = "BLOCK"
                allowed = False

        # Enforce the registered input schema before handing data to a tool.
        schema = tool_def.input_schema
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        schema_errors = []
        if not isinstance(properties, dict) or not isinstance(required, list):
            schema_errors.append("Tool schema is invalid.")
        else:
            for field_name in required:
                if field_name not in arguments:
                    schema_errors.append("A required tool argument is missing.")
            if schema.get("additionalProperties", True) is False:
                if set(arguments) - set(properties):
                    schema_errors.append("Unknown tool arguments were supplied.")
            expected_types = {"string": str, "object": dict, "array": list, "boolean": bool, "integer": int, "number": (int, float)}
            for field_name, value in arguments.items():
                definition = properties.get(field_name, {})
                expected = expected_types.get(definition.get("type")) if isinstance(definition, dict) else None
                if expected and (not isinstance(value, expected) or (expected is int and isinstance(value, bool))):
                    schema_errors.append("A tool argument has the wrong JSON type.")
                    break
        if schema_errors:
            violations.extend(schema_errors)
            decision = "BLOCK"
            allowed = False

        # 3a. Command Injection Check
        if _DANGEROUS_SHELL_COMMANDS.search(arg_string):
            violations.append("Dangerous shell command pattern was intercepted.")
            decision = "BLOCK"
            allowed = False

        # 3b. Path Traversal Check
        if _PATH_TRAVERSAL.search(decoded_arg_string):
            violations.append("Path traversal or sensitive credential path access was intercepted.")
            decision = "BLOCK"
            allowed = False

        # 3c. SQL Injection Check
        if _SQL_INJECTION.search(arg_string):
            violations.append("SQL injection pattern was intercepted.")
            decision = "BLOCK"
            allowed = False

        # 3d. DLP Scan on Arguments (Aadhaar, PAN, API Keys, Passwords)
        dlp_findings = scan_text(arg_string, source="mcp_arguments", policy=DEFAULT_POLICY)
        if dlp_findings:
            has_blocking_pii = any(f.action == "block" for f in dlp_findings)
            has_maskable_pii = any(f.action in ("mask", "redact") for f in dlp_findings)
            
            for f in dlp_findings:
                violations.append(f"DLP Finding in tool arguments: {f.label} ({f.category})")

            if has_blocking_pii:
                decision = "BLOCK"
                allowed = False
            elif has_maskable_pii and allowed:
                decision = "MASK_AND_ALLOW"
                # Sanitize every string recursively, including nested objects
                # and arrays, before passing arguments to the tool handler.
                def sanitize(value: Any) -> Any:
                    if isinstance(value, str):
                        return apply_action_to_text(
                            value, scan_text(value, source="mcp_arguments", policy=DEFAULT_POLICY)
                        )
                    if isinstance(value, dict):
                        return {key: sanitize(item) for key, item in value.items()}
                    if isinstance(value, list):
                        return [sanitize(item) for item in value]
                    return value

                sanitized_args = sanitize(sanitized_args)

        # 3e. Lexical concept-anchor and jailbreak-pattern checks on argument strings
        if allowed:
            jepa_res = jepa_analyzer.analyze(arg_string)
            if jepa_res.is_adversarial:
                violations.append("Lexical anchor screening flagged the argument payload as suspicious.")
                decision = "BLOCK"
                allowed = False

            jeb_res = jeb_engine.scan(arg_string)
            if jeb_res.is_jailbreak_attempt:
                violations.append(
                    f"JEB Jailbreak Scanner intercepted attack in argument: {jeb_res.attack_family}"
                )
                decision = "BLOCK"
                allowed = False

        latency = (time.perf_counter() - t0) * 1000.0
        reason = "; ".join(violations) if violations else "Tool parameters verified and authorized."

        # Audit event
        event = {
            "timestamp": time.time(),
            "tool_name": tool_name,
            "user_role": user_role,
            "decision": decision,
            "allowed": allowed,
            "violations_count": len(violations),
            "reason": reason,
            "latency_ms": round(latency, 3),
        }
        self._audit_log.append(event)

        return MCPToolInspectionResult(
            allowed=allowed,
            tool_name=tool_name,
            decision=decision,
            reason=reason,
            violations=violations,
            sanitized_arguments=sanitized_args,
            latency_ms=round(latency, 3),
        )

    def handle_json_rpc(
        self,
        request_data: Dict[str, Any],
        user_role: str = "employee",
        user_clearance: str = "PUBLIC",
    ) -> Dict[str, Any]:
        """
        Handle standard JSON-RPC 2.0 MCP requests.
        Supports methods:
          - tools/list
          - tools/call
          - prompts/list
          - resources/list
        """
        req_id = request_data.get("id")
        method = request_data.get("method")
        params = request_data.get("params", {})

        if request_data.get("jsonrpc") != "2.0":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32600, "message": "Invalid Request: Must specify jsonrpc 2.0"},
            }

        if not isinstance(method, str) or not isinstance(params, dict):
            return {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32600, "message": "Invalid Request: method and params must be valid."},
            }

        # 1. tools/list
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.list_tools()},
            }

        # 2. tools/call
        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            if not isinstance(tool_name, str) or not isinstance(arguments, dict):
                return {
                    "jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32602, "message": "Invalid tool name or arguments."},
                }

            # Intercept and inspect tool call
            inspection = self.inspect_tool_call(
                tool_name=tool_name,
                arguments=arguments,
                user_role=user_role,
                user_clearance=user_clearance or self.role_clearance(user_role),
            )

            if not inspection.allowed:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": True,
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"[Data Sentry MCP Security Block]\n"
                                    f"Tool call '{tool_name}' was blocked by gateway policy.\n"
                                    f"Reason: {inspection.reason}"
                                ),
                            }
                        ],
                        "security": {
                            "decision": inspection.decision,
                            "violations": inspection.violations,
                            "latency_ms": inspection.latency_ms,
                        },
                    },
                }

            # If tool allowed (or sanitized)
            handler = self._handlers.get(tool_name)
            output = handler(inspection.sanitized_arguments) if handler else "Tool executed successfully."

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": False,
                    "content": [{"type": "text", "text": str(output)}],
                    "security": {
                        "decision": inspection.decision,
                        "sanitized_arguments": inspection.sanitized_arguments,
                        "latency_ms": inspection.latency_ms,
                    },
                },
            }

        # 3. prompts/list
        if method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "prompts": [
                        {
                            "name": "safe_summary",
                            "description": "Secure summary prompt with DLP instructions",
                            "arguments": [{"name": "topic", "required": True}],
                        }
                    ]
                },
            }

        # Unknown method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"},
        }


# Singleton
mcp_gateway = MCPGateway()
