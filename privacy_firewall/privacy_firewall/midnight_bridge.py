"""Bridge between the Python audit log and the Midnight Compact contract.

``midnight/policy_attestation.compact`` exposes:

    ledger  attested: Map<Opaque<"Bytes32">, Boolean>
    circuit recordAttestation(decisionHash: Opaque<"Bytes32">): []
    circuit isAttested(decisionHash: Opaque<"Bytes32">): Boolean

so the only thing that ever goes on-chain is a 32-byte hash of a policy
decision. This module turns a :class:`SecurityDecision` (or an
``AuditEntry`` / ``FieldDecision`` / plain dict) into:

  * ``format_decision_for_compact`` - the exact call shape the circuit
    wants: ``{"public": {"decisionHash": "0x.."}, ...}`` plus the full
    off-chain record it commits to.
  * ``generate_zk_witness`` - public inputs (hashed request id, policy
    id, decision enum, the disclosed decision hash) vs private inputs
    (raw field names, agent identity, timestamp, reason).
  * ``export_audit_batch`` - an HMAC-SHA256 signed JSON batch of many
    decisions plus a single SHA-256 state commitment over all of them.

The decision-hash preimage matches the contract's own comment:
``agent | field | decision | reason | timestamp``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .decision import Decision

CONTRACT_PATH = Path(__file__).resolve().parent.parent / "midnight" / "policy_attestation.compact"

# Compact enums are integers; fix an explicit, stable mapping.
DECISION_ENUM: dict[str, int] = {
    Decision.ALLOW.value: 0,
    Decision.DENY.value: 1,
    Decision.AGGREGATE_ONLY.value: 2,
}

# Ordered preimage fields for the on-chain decision hash.
_HASH_FIELDS = ("agent_id", "field", "decision", "reason", "timestamp")

_BYTES32_RE = re.compile(r"^0x[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _as_bytes32(hex64: str) -> str:
    h = hex64[2:] if hex64.startswith("0x") else hex64
    if len(h) != 64 or any(c not in "0123456789abcdef" for c in h.lower()):
        raise ValueError(f"not a 32-byte hex value: {hex64!r}")
    return "0x" + h.lower()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _normalise_decision(value: Any) -> str:
    if isinstance(value, Decision):
        return value.value
    s = str(value).strip().lower()
    if s not in DECISION_ENUM:
        raise ValueError(f"unknown decision {value!r}; expected one of {sorted(DECISION_ENUM)}")
    return s


# ---------------------------------------------------------------------------
# SecurityDecision
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecurityDecision:
    """Normalised, hashable view of one policy decision."""

    request_id: str
    agent_id: str
    field: str
    decision: str                    # allow | deny | aggregate_only
    reason: str
    timestamp: str
    policy_id: str = "analytics-agent@v1"
    resource: str = "employees"

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", _normalise_decision(self.decision))

    # -- construction ------------------------------------------------

    @classmethod
    def coerce(cls, obj: Any, policy_id: str | None = None) -> "SecurityDecision":
        if isinstance(obj, SecurityDecision):
            return obj if policy_id is None else _replace_policy(obj, policy_id)

        if isinstance(obj, dict):
            data = dict(obj)
            fields = data.get("fields")
            field_val = data.get("field") or (fields[0] if fields else "")
            return cls(
                request_id=str(data.get("request_id", "")),
                agent_id=str(data.get("agent_id") or data.get("agent") or ""),
                field=str(field_val),
                decision=data["decision"],
                reason=str(data.get("reason", "")),
                timestamp=str(data.get("timestamp", "")),
                policy_id=str(policy_id or data.get("policy_id") or "analytics-agent@v1"),
                resource=str(data.get("resource", "employees")),
            )

        # AuditEntry / FieldDecision - duck typed
        return cls(
            request_id=str(getattr(obj, "request_id", "")),
            agent_id=str(getattr(obj, "agent", getattr(obj, "agent_id", ""))),
            field=str(getattr(obj, "field", "")),
            decision=getattr(obj, "decision"),
            reason=str(getattr(obj, "reason", "")),
            timestamp=str(getattr(obj, "timestamp", "")),
            policy_id=str(policy_id or "analytics-agent@v1"),
            resource=str(getattr(obj, "resource", "employees")),
        )

    # -- views -----------------------------------------------------

    @property
    def decision_enum(self) -> int:
        return DECISION_ENUM[self.decision]

    def hash_preimage(self) -> str:
        return "|".join(str(getattr(self, k)) for k in _HASH_FIELDS)

    def decision_hash(self) -> str:
        """The Bytes32 key attested on-chain. Deterministic."""
        return _as_bytes32(_sha256_hex(self.hash_preimage()))

    def to_struct(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "policy_id": self.policy_id,
            "resource": self.resource,
            "field": self.field,
            "fields": [self.field],
            "decision": self.decision,
            "decision_enum": self.decision_enum,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


def _replace_policy(sd: SecurityDecision, policy_id: str) -> SecurityDecision:
    return SecurityDecision(
        request_id=sd.request_id, agent_id=sd.agent_id, field=sd.field,
        decision=sd.decision, reason=sd.reason, timestamp=sd.timestamp,
        policy_id=policy_id, resource=sd.resource,
    )


# ---------------------------------------------------------------------------
# contract interface parsing
# ---------------------------------------------------------------------------

def parse_contract_interface(path: str | Path = CONTRACT_PATH) -> dict[str, Any]:
    text = Path(path).read_text()
    circuits = re.findall(r"export\s+circuit\s+(\w+)", text)
    ledgers = re.findall(r"export\s+ledger\s+(\w+)", text)
    key_type = "Bytes32" if 'Opaque<"Bytes32">' in text else None
    return {
        "contract": Path(path).name,
        "ledger": ledgers[0] if ledgers else None,
        "circuits": circuits,
        "attest_circuit": "recordAttestation",
        "query_circuit": "isAttested",
        "key_type": key_type,
    }


# ---------------------------------------------------------------------------
# MidnightBridge
# ---------------------------------------------------------------------------

class MidnightBridge:
    """Formats and signs audit decisions for Midnight attestation."""

    SCHEMA = "midnight.policy_attestation.batch/v1"

    def __init__(
        self,
        decisions: Iterable[Any] | None = None,
        *,
        signing_key: bytes = b"midnight-dev-signing-key",
        key_id: str = "dev-hmac-key",
        policy_id: str = "analytics-agent@v1",
        timestamp_fn: Callable[[], str] | None = None,
        contract_path: str | Path = CONTRACT_PATH,
    ) -> None:
        self.signing_key = signing_key
        self.key_id = key_id
        self.policy_id = policy_id
        self._now = timestamp_fn or (lambda: datetime.now(timezone.utc).isoformat())
        self.interface = parse_contract_interface(contract_path)
        if self.interface["attest_circuit"] not in self.interface["circuits"]:
            raise ValueError(
                f"contract {self.interface['contract']} has no "
                f"{self.interface['attest_circuit']} circuit"
            )
        self._decisions: list[SecurityDecision] = [
            SecurityDecision.coerce(d, self.policy_id) for d in (decisions or [])
        ]

    # -- constructors ------------------------------------------------

    @classmethod
    def from_audit_log(cls, audit_log: Any, **kwargs: Any) -> "MidnightBridge":
        return cls(list(audit_log.entries()), **kwargs)

    def add(self, decision: Any) -> SecurityDecision:
        sd = SecurityDecision.coerce(decision, self.policy_id)
        self._decisions.append(sd)
        return sd

    @property
    def decisions(self) -> list[SecurityDecision]:
        return list(self._decisions)

    def contract_interface(self) -> dict[str, Any]:
        return dict(self.interface)

    # -- 1. compact call shape ------------------------------------

    def format_decision_for_compact(self, decision: Any) -> dict[str, Any]:
        sd = SecurityDecision.coerce(decision, self.policy_id)
        h = sd.decision_hash()
        return {
            "contract": self.interface["contract"],
            "circuit": self.interface["attest_circuit"],
            "ledger": self.interface["ledger"],
            "key_type": self.interface["key_type"],
            # exactly what recordAttestation(decisionHash) receives:
            "public": {"decisionHash": h},
            "tuple": [h],
            # full record the hash commits to (kept off-chain):
            "struct": sd.to_struct(),
        }

    # -- 2. zk witness -------------------------------------------

    def generate_zk_witness(self, decision_payload: dict[str, Any] | Any) -> dict[str, Any]:
        if isinstance(decision_payload, SecurityDecision):
            struct = decision_payload.to_struct()
            h = decision_payload.decision_hash()
        elif isinstance(decision_payload, dict) and "struct" in decision_payload:
            struct = decision_payload["struct"]
            h = decision_payload.get("public", {}).get("decisionHash") \
                or SecurityDecision.coerce(struct, self.policy_id).decision_hash()
        else:
            sd = SecurityDecision.coerce(decision_payload, self.policy_id)
            struct, h = sd.to_struct(), sd.decision_hash()

        decision_val = _normalise_decision(struct["decision"])
        return {
            "circuit": self.interface["attest_circuit"],
            "public": {
                "request_id_hash": _sha256_hex(str(struct.get("request_id", ""))),
                "policy_id": struct.get("policy_id", self.policy_id),
                "decision": decision_val,
                "decision_enum": DECISION_ENUM[decision_val],
                "decisionHash": _as_bytes32(h),
            },
            "private": {
                "request_id": str(struct.get("request_id", "")),
                "agent_id": str(struct.get("agent_id", "")),
                "fields": list(struct.get("fields") or [struct.get("field", "")]),
                "reason": str(struct.get("reason", "")),
                "timestamp": str(struct.get("timestamp", "")),
            },
        }

    # -- 3. signed batch export --------------------------------

    def build_batch(self) -> dict[str, Any]:
        records = []
        for sd in self._decisions:
            payload = self.format_decision_for_compact(sd)
            records.append({
                "decision_hash": sd.decision_hash(),
                "compact": payload,
                "witness": self.generate_zk_witness(payload),
            })

        commitment = "0x" + _sha256_hex(
            "".join(r["decision_hash"][2:] for r in records)
        )
        body = {
            "schema": self.SCHEMA,
            "contract": self.interface["contract"],
            "circuit": self.interface["attest_circuit"],
            "ledger": self.interface["ledger"],
            "key_type": self.interface["key_type"],
            "generated_at": self._now(),
            "count": len(records),
            "state_commitment": commitment,
            "decisions": records,
        }
        signature = hmac.new(
            self.signing_key, _canonical_json(body).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return {
            **body,
            "signature": {
                "alg": "HMAC-SHA256",
                "key_id": self.key_id,
                "value": signature,
            },
        }

    def export_audit_batch(self, file_path: str | Path) -> dict[str, Any]:
        batch = self.build_batch()
        Path(file_path).write_text(json.dumps(batch, indent=2, ensure_ascii=False))
        return batch

    # -- verification -----------------------------------------

    @staticmethod
    def verify_batch(batch: dict[str, Any], signing_key: bytes) -> bool:
        sig = (batch.get("signature") or {}).get("value", "")
        body = {k: v for k, v in batch.items() if k != "signature"}
        expected = hmac.new(
            signing_key, _canonical_json(body).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(sig, expected)
