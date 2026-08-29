"""Access decisions the policy engine can return for a single field."""

from enum import Enum


class Decision(Enum):
    """The three outcomes a policy rule can produce for a field.

    ALLOW           - the raw value may be returned to the agent.
    DENY            - the field must never reach the agent, in any form.
    AGGREGATE_ONLY  - individual values are never exposed; only summary
                      statistics (sum, average, count, min, max) may be
                      computed and returned.
    """

    ALLOW = "allow"
    DENY = "deny"
    AGGREGATE_ONLY = "aggregate_only"

    @classmethod
    def from_str(cls, value: str) -> "Decision":
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            valid = ", ".join(d.value for d in cls)
            raise ValueError(
                f"Unknown decision '{value}'. Expected one of: {valid}"
            ) from exc
