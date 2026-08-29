"""AI agent, mock data source, and the inbound request firewall.

This ties the pieces together into the flow from the project README:

    AIAgent  --structured request-->  PrivacyFirewallMiddleware
                                          |  PolicyEngine   (may this agent read this field?)
                                          |  DataMinimizer  (aggregate-only / drop denied)
                                          |  AuditLog       (record every decision, hash-chained)
                                          v
                                      sanitized payload  OR  denial   -->  AIAgent

Key property: the ``AIAgent`` never holds a reference to ``MockEmployeeDB``.
The only path from agent to data runs through the middleware, so the
policy engine sits on every read.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any, Iterable

from .audit import AuditLog
from .data_minimizer import DataMinimizer
from .decision import Decision
from .policy_engine import PolicyEngine

# AuditLogger is the name used elsewhere in the project docs for this class.
AuditLogger = AuditLog

READ = "read"
AGGREGATE = "aggregate"
_VALID_OPERATIONS = frozenset({READ, AGGREGATE})

ALLOW = "ALLOW"
DENY = "DENY"

# Canary tokens seeded into the mock DB. If one ever shows up in an
# agent-visible payload or an LLM response, data that was policy-denied
# has leaked. The OutputFirewall consumes this same list.
CANARY_TOKENS: list[str] = [
    "CANARY-SECRET-7f3a91",
    "CANARY-SECRET-b52e08",
    "CANARY-SECRET-c19d44",
]

# Maps a request `resource` to the field-name prefix the policy file uses.
_RESOURCE_PREFIX = {"employees": "employee"}

# Record dict key -> policy field suffix, where they differ.
_KEY_TO_POLICY_SUFFIX = {"id": "employee_id"}


# ---------------------------------------------------------------------------
# Mock database
# ---------------------------------------------------------------------------

class MockEmployeeDB:
    """Synthetic employee store. Stands in for a real database.

    Fields per row: id, name, email, phone, department, salary, notes.
    ``notes`` carries an embedded canary token per row.

    Only the middleware is expected to call :meth:`records`. Nothing hands
    this object to an :class:`AIAgent`.
    """

    FIELDS = ("id", "name", "email", "phone", "department", "salary", "notes")

    _ROWS: list[dict[str, Any]] = [
        {
            "id": 1, "name": "Alice Johnson", "email": "alice@company.com",
            "phone": "(415) 555-0132", "department": "Engineering", "salary": 90000,
            "notes": f"Hired 2019. Internal ref {CANARY_TOKENS[0]}.",
        },
        {
            "id": 2, "name": "Bob Nguyen", "email": "bob@company.com",
            "phone": "(415) 555-0170", "department": "Engineering", "salary": 85000,
            "notes": f"Team lead. Internal ref {CANARY_TOKENS[1]}.",
        },
        {
            "id": 3, "name": "Sarah Patel", "email": "sarah@company.com",
            "phone": "(628) 555-0199", "department": "HR", "salary": 62000,
            "notes": f"Benefits admin. Internal ref {CANARY_TOKENS[2]}.",
        },
        {
            "id": 4, "name": "Diego Ramirez", "email": "diego@company.com",
            "phone": "(628) 555-0143", "department": "Sales", "salary": 71000,
            "notes": "Quota carrier, west region.",
        },
        {
            "id": 5, "name": "Mei Lin", "email": "mei@company.com",
            "phone": "(415) 555-0188", "department": "Engineering", "salary": 96000,
            "notes": "On-call rotation A.",
        },
    ]

    def __init__(self) -> None:
        # Per-instance copy so tests (and canary injection) don't mutate
        # the shared class-level template.
        self._rows: list[dict[str, Any]] = copy.deepcopy(self._ROWS)

    def records(self, resource: str = "employees") -> list[dict[str, Any]]:
        """Return a deep copy of all rows. Copy so callers cannot mutate
        the backing store."""
        if resource != "employees":
            raise KeyError(f"Unknown resource '{resource}'")
        return copy.deepcopy(self._rows)

    def __len__(self) -> int:
        return len(self._rows)


# ---------------------------------------------------------------------------
# Firewall response
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FirewallResponse:
    """What the middleware hands back to the agent."""

    decision: str                                   # ALLOW | DENY
    agent_id: str
    operation: str
    payload: dict[str, Any] | None
    denied_fields: list[str] = dataclass_field(default_factory=list)
    reason: str = ""
    audit_ref: str | None = None                    # hash of the last audit entry

    @property
    def is_allowed(self) -> bool:
        return self.decision == ALLOW

    @property
    def is_denied(self) -> bool:
        return self.decision == DENY


# ---------------------------------------------------------------------------
# Inbound firewall
# ---------------------------------------------------------------------------

class PrivacyFirewallMiddleware:
    """Intercepts agent requests, enforces policy, minimizes, audits."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        database: MockEmployeeDB,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.policy_engine = policy_engine
        self.database = database
        self.audit_log = audit_log or AuditLog()
        # Share the one audit chain with the minimizer.
        self.minimizer = DataMinimizer(policy_engine, self.audit_log)

    @classmethod
    def from_policy_file(
        cls, path: str | Path, database: MockEmployeeDB | None = None
    ) -> "PrivacyFirewallMiddleware":
        return cls(PolicyEngine.from_yaml(path), database or MockEmployeeDB())

    # -- request handling --------------------------------------------------

    def handle_request(self, request: dict[str, Any]) -> FirewallResponse:
        """Validate, evaluate, minimize, audit, and respond. Never raises
        on a policy miss; only on a structurally invalid request."""
        agent_id, resource, operation, fields, _query = self._parse(request)
        prefix = _RESOURCE_PREFIX.get(resource)
        if prefix is None:
            raise ValueError(f"Unknown resource '{resource}'")

        records = self.database.records(resource)

        if operation == AGGREGATE:
            response = self._handle_aggregate(agent_id, prefix, fields, records)
        else:
            response = self._handle_read(agent_id, prefix, fields, records)
        return response

    # backwards-friendly alias
    intercept = handle_request

    def safe_handle_request(self, request: Any) -> FirewallResponse:
        """Fail-closed wrapper around :meth:`handle_request`.

        A structurally invalid or malformed request (not a dict, missing
        keys, bad operation, unknown resource, wrong field types, or any
        unexpected internal error) resolves to a clean ``DENY`` response
        instead of propagating an exception or a traceback. No database
        record is ever read on this path.
        """
        try:
            return self.handle_request(request)
        except (ValueError, TypeError, KeyError) as exc:
            reason = f"Malformed request rejected: {exc}"
        except Exception:  # pragma: no cover - defensive catch-all
            reason = "Malformed request rejected: internal error"

        agent_id = operation = ""
        if isinstance(request, dict):
            agent_id = str(request.get("agent_id", "") or "")
            operation = str(request.get("operation", "") or "")
        return FirewallResponse(
            decision=DENY,
            agent_id=agent_id,
            operation=operation,
            payload=None,
            denied_fields=[],
            reason=reason,
            audit_ref=self._audit_ref(),
        )

    # -- operations ------------------------------------------------------

    def _handle_read(
        self, agent_id: str, prefix: str, fields: list[str],
        records: list[dict[str, Any]],
    ) -> FirewallResponse:
        allowed: list[str] = []
        denied: list[str] = []

        for f in fields:
            fd = self.policy_engine.evaluate_field(agent_id, self._policy_name(prefix, f))
            self.audit_log.record(fd.agent, fd.field, fd.decision, fd.reason)
            if fd.decision is Decision.ALLOW:
                allowed.append(f)
            else:
                # AGGREGATE_ONLY and DENY both fail a raw read.
                denied.append(f)

        if not allowed:
            return self._denied(
                agent_id, READ, denied,
                "All requested fields are denied for a raw read",
            )

        sanitized_rows = [{f: row.get(f) for f in allowed} for row in records]
        return FirewallResponse(
            decision=ALLOW,
            agent_id=agent_id,
            operation=READ,
            payload={"records": sanitized_rows, "returned_fields": allowed},
            denied_fields=denied,
            reason="Raw read of policy-allowed fields",
            audit_ref=self._audit_ref(),
        )

    def _handle_aggregate(
        self, agent_id: str, prefix: str, fields: list[str],
        records: list[dict[str, Any]],
    ) -> FirewallResponse:
        requested = [self._policy_name(prefix, f) for f in fields]
        # minimize() logs every field decision into the shared audit log.
        result = self.minimizer.minimize(agent_id, records, requested)

        # Re-key from 'employee.salary' back to 'salary' for the payload.
        allowed_fields = {
            self._short(k): v for k, v in result.allowed_fields.items()
        }
        aggregates = {self._short(k): v for k, v in result.aggregates.items()}
        denied = [self._short(k) for k in result.denied_fields]

        if not allowed_fields and not aggregates:
            return self._denied(
                agent_id, AGGREGATE, denied,
                "No requested field survived minimization",
            )

        return FirewallResponse(
            decision=ALLOW,
            agent_id=agent_id,
            operation=AGGREGATE,
            payload={"aggregates": aggregates, "allowed_fields": allowed_fields},
            denied_fields=denied,
            reason="Aggregate-only view; raw values never exposed",
            audit_ref=self._audit_ref(),
        )

    # -- helpers -------------------------------------------------------

    @staticmethod
    def _parse(request: dict[str, Any]):
        if not isinstance(request, dict):
            raise TypeError("request must be a dict")
        try:
            agent_id = request["agent_id"]
            resource = request["resource"]
            operation = request["operation"]
        except KeyError as exc:
            raise ValueError(f"request missing required key: {exc}") from exc
        fields = request.get("fields", [])
        query = request.get("query", "")
        if operation not in _VALID_OPERATIONS:
            raise ValueError(
                f"operation must be one of {sorted(_VALID_OPERATIONS)}, got '{operation}'"
            )
        if not isinstance(fields, (list, tuple)) or not all(isinstance(x, str) for x in fields):
            raise ValueError("fields must be a list of strings")
        if not fields:
            raise ValueError("request must name at least one field")
        return agent_id, resource, operation, list(fields), query

    @staticmethod
    def _policy_name(prefix: str, field_key: str) -> str:
        suffix = _KEY_TO_POLICY_SUFFIX.get(field_key, field_key)
        return f"{prefix}.{suffix}"

    @staticmethod
    def _short(policy_field: str) -> str:
        suffix = policy_field.rsplit(".", 1)[-1]
        for key, mapped in _KEY_TO_POLICY_SUFFIX.items():
            if mapped == suffix:
                return key
        return suffix

    def _denied(
        self, agent_id: str, operation: str, denied: list[str], reason: str
    ) -> FirewallResponse:
        return FirewallResponse(
            decision=DENY,
            agent_id=agent_id,
            operation=operation,
            payload=None,
            denied_fields=denied,
            reason=reason,
            audit_ref=self._audit_ref(),
        )

    def _audit_ref(self) -> str | None:
        entries = self.audit_log.entries()
        return entries[-1].entry_hash if entries else None


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class AIAgent:
    """An analytics / assistant agent. Talks to data only via the firewall."""

    def __init__(
        self,
        firewall: PrivacyFirewallMiddleware,
        agent_id: str = "analytics-agent",
        resource: str = "employees",
    ) -> None:
        self._firewall = firewall
        self.agent_id = agent_id
        self.resource = resource

    def build_request(
        self, operation: str, fields: Iterable[str], query: str = ""
    ) -> dict[str, Any]:
        """Form the structured request the firewall expects."""
        return {
            "agent_id": self.agent_id,
            "resource": self.resource,
            "operation": operation,
            "fields": list(fields),
            "query": query,
        }

    def request_read(self, fields: Iterable[str], query: str = "") -> FirewallResponse:
        return self._firewall.handle_request(self.build_request(READ, fields, query))

    def request_aggregate(self, fields: Iterable[str], query: str = "") -> FirewallResponse:
        return self._firewall.handle_request(self.build_request(AGGREGATE, fields, query))

    def read_database(self, *_args, **_kwargs):
        """Explicitly unsupported. The agent has no direct data path."""
        raise PermissionError(
            "AIAgent cannot read the database directly; route through the firewall"
        )
