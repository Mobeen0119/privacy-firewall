"""Tamper-evident audit log for security decisions.

This is deliberately narrow in scope. It does NOT prove anything about
what an external LLM provider does with data after it receives it —
see the project README, section 13 and 23, on that limitation. What it
does prove is:

  * a specific decision was recorded, in order,
  * and the record has not been altered since,

by chaining each entry's hash into the next one, the same way a
tamper-evident log or a minimal blockchain does. If the crypto/ZKP
teammate wants to extend this into a signed or zero-knowledge scheme
later, this class is the append point.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .decision import Decision

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    request_id: str
    agent: str
    field: str
    decision: Decision
    reason: str
    timestamp: str
    prev_hash: str
    entry_hash: str


def _payload(entry_id: str, agent: str, field_name: str, decision: Decision,
             reason: str, timestamp: str, prev_hash: str) -> str:
    return "|".join([entry_id, agent, field_name, decision.value, reason, timestamp, prev_hash])


class AuditLog:
    """An append-only, hash-chained log of policy decisions."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def record(self, agent: str, field_name: str, decision: Decision, reason: str) -> AuditEntry:
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        request_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = _payload(request_id, agent, field_name, decision, reason, timestamp, prev_hash)
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        entry = AuditEntry(
            request_id=request_id,
            agent=agent,
            field=field_name,
            decision=decision,
            reason=reason,
            timestamp=timestamp,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def verify_chain(self) -> bool:
        """Recompute every hash and confirm the chain is intact.

        Returns False if any entry was edited, reordered, or removed
        from the middle of the log after being written.
        """
        prev_hash = GENESIS_HASH
        for entry in self._entries:
            expected = hashlib.sha256(
                _payload(
                    entry.request_id, entry.agent, entry.field,
                    entry.decision, entry.reason, entry.timestamp, prev_hash,
                ).encode("utf-8")
            ).hexdigest()
            if expected != entry.entry_hash:
                return False
            prev_hash = entry.entry_hash
        return True
