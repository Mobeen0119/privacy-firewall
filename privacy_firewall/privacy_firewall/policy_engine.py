"""Policy engine.

Holds per agent field permissions and decides, for a given agent and
field, whether that field may be read and in what form (full value,
aggregate only, or not at all).

Design principle (see project README, "Fail closed"): if no policy
exists for an agent, or a policy exists but says nothing about a
specific field, the answer is DENY. An engine should never grant
access by omission.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

from .decision import Decision


@dataclass(frozen=True)
class FieldDecision:
    """The outcome of evaluating one field for one agent."""

    agent: str
    field: str
    decision: Decision
    reason: str


class PolicyEngine:
    """Evaluates field-level read permissions for named agents."""

    def __init__(self) -> None:
        self._policies: dict[str, dict[str, Decision]] = {}

    def register_policy(self, agent: str, permissions: dict[str, str]) -> None:
        """Register (or replace) the policy for a single agent.

        `permissions` maps a field name (e.g. "employee.salary") to a
        decision string ("allow", "deny", "aggregate_only").
        """
        parsed = {field: Decision.from_str(value) for field, value in permissions.items()}
        self._policies[agent] = parsed

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PolicyEngine":
        """Build an engine from a YAML file.

        Expected shape:

            agent: analytics-agent
            permissions:
              employee.department:
                read: allow
              employee.salary:
                read: aggregate_only
              employee.name:
                read: deny

        Multiple documents (one per agent) may be concatenated in a
        single file with '---' separators.
        """
        engine = cls()
        text = Path(path).read_text()
        for doc in yaml.safe_load_all(text):
            if not doc:
                continue
            agent = doc["agent"]
            raw_permissions = doc.get("permissions", {})
            flat_permissions = {
                field: rule["read"] for field, rule in raw_permissions.items()
            }
            engine.register_policy(agent, flat_permissions)
        return engine

    def evaluate_field(self, agent: str, field: str) -> FieldDecision:
        """Evaluate a single field for a single agent. Never raises."""
        agent_policy = self._policies.get(agent)
        if agent_policy is None:
            return FieldDecision(
                agent, field, Decision.DENY,
                f"No policy registered for agent '{agent}'; failing closed",
            )
        decision = agent_policy.get(field)
        if decision is None:
            return FieldDecision(
                agent, field, Decision.DENY,
                f"Field '{field}' is not covered by {agent}'s policy; failing closed",
            )
        return FieldDecision(agent, field, decision, "Matched explicit policy rule")

    def evaluate_request(self, agent: str, fields: Iterable[str]) -> list[FieldDecision]:
        """Evaluate every field in a request. Order is preserved."""
        return [self.evaluate_field(agent, field) for field in fields]

    def known_agents(self) -> list[str]:
        return sorted(self._policies)
