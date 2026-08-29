import hashlib
import hmac
import json
from pathlib import Path

import pytest

from privacy_firewall import AuditLog, Decision
from privacy_firewall.agent import AIAgent, MockEmployeeDB, PrivacyFirewallMiddleware
from privacy_firewall.midnight_bridge import (
    CONTRACT_PATH,
    DECISION_ENUM,
    MidnightBridge,
    SecurityDecision,
    parse_contract_interface,
)

POLICY_PATH = Path(__file__).parent.parent / "policies" / "analytics_agent.yaml"
KEY = b"unit-test-key"

FIXED_TS = "2026-01-01T00:00:00+00:00"


def sd(**over):
    base = dict(
        request_id="req-1",
        agent_id="analytics-agent",
        field="employee.email",
        decision="deny",
        reason="Matched explicit policy rule",
        timestamp=FIXED_TS,
    )
    base.update(over)
    return SecurityDecision(**base)


@pytest.fixture
def bridge():
    return MidnightBridge(
        [sd(), sd(field="employee.salary", decision="aggregate_only", request_id="req-2")],
        signing_key=KEY,
        timestamp_fn=lambda: FIXED_TS,
    )


# =====================================================================
# contract interface / schema conformity
# =====================================================================

def test_contract_file_exists():
    assert CONTRACT_PATH.exists()


def test_parsed_interface_matches_compact_source():
    iface = parse_contract_interface()
    assert iface["ledger"] == "attested"
    assert set(iface["circuits"]) == {"recordAttestation", "isAttested"}
    assert iface["key_type"] == "Bytes32"


def test_bridge_interface_exposes_same_names(bridge):
    iface = bridge.contract_interface()
    assert iface["attest_circuit"] == "recordAttestation"
    assert iface["query_circuit"] == "isAttested"
    assert iface["ledger"] == "attested"


def test_bridge_rejects_contract_without_attest_circuit(tmp_path):
    bogus = tmp_path / "x.compact"
    bogus.write_text('export ledger attested: Map<Opaque<"Bytes32">, Boolean>;\n')
    with pytest.raises(ValueError):
        MidnightBridge([], contract_path=bogus)


# =====================================================================
# hash determinism
# =====================================================================

def test_decision_hash_is_deterministic():
    assert sd().decision_hash() == sd().decision_hash()


def test_decision_hash_matches_documented_preimage():
    d = sd()
    preimage = "analytics-agent|employee.email|deny|Matched explicit policy rule|" + FIXED_TS
    expected = "0x" + hashlib.sha256(preimage.encode()).hexdigest()
    assert d.hash_preimage() == preimage
    assert d.decision_hash() == expected


def test_decision_hash_is_bytes32_shaped():
    h = sd().decision_hash()
    assert h.startswith("0x") and len(h) == 66
    assert all(c in "0123456789abcdef" for c in h[2:])


@pytest.mark.parametrize("field_over", [
    {"agent_id": "other-agent"},
    {"field": "employee.phone"},
    {"decision": "allow"},
    {"reason": "different reason"},
    {"timestamp": "2026-02-02T00:00:00+00:00"},
])
def test_any_field_change_changes_hash(field_over):
    assert sd().decision_hash() != sd(**field_over).decision_hash()


def test_request_id_does_not_affect_decision_hash():
    # request_id is private / hashed separately, not part of the on-chain key
    assert sd(request_id="a").decision_hash() == sd(request_id="b").decision_hash()


def test_hash_stable_across_bridge_instances(bridge):
    other = MidnightBridge([sd()], signing_key=b"different", timestamp_fn=lambda: FIXED_TS)
    assert other.format_decision_for_compact(sd())["public"]["decisionHash"] == \
        bridge.format_decision_for_compact(sd())["public"]["decisionHash"]


# =====================================================================
# format_decision_for_compact
# =====================================================================

def test_format_shape_conforms_to_compact(bridge):
    out = bridge.format_decision_for_compact(sd())
    assert out["circuit"] == "recordAttestation"
    assert out["ledger"] == "attested"
    assert out["key_type"] == "Bytes32"
    assert set(out["public"]) == {"decisionHash"}
    assert out["tuple"] == [out["public"]["decisionHash"]]
    assert out["public"]["decisionHash"] == sd().decision_hash()


def test_format_struct_carries_full_offchain_record(bridge):
    struct = bridge.format_decision_for_compact(sd())["struct"]
    assert struct["decision"] == "deny"
    assert struct["decision_enum"] == DECISION_ENUM["deny"] == 1
    assert struct["fields"] == ["employee.email"]
    assert struct["policy_id"] == "analytics-agent@v1"


def test_format_accepts_audit_entry(bridge):
    log = AuditLog()
    entry = log.record("analytics-agent", "employee.email", Decision.DENY, "protected")
    out = bridge.format_decision_for_compact(entry)
    assert out["public"]["decisionHash"].startswith("0x")
    assert out["struct"]["agent_id"] == "analytics-agent"
    assert out["struct"]["field"] == "employee.email"


def test_format_rejects_unknown_decision(bridge):
    with pytest.raises(ValueError):
        bridge.format_decision_for_compact({
            "agent": "a", "field": "f", "decision": "maybe", "reason": "", "timestamp": "",
        })


# =====================================================================
# generate_zk_witness
# =====================================================================

def test_witness_public_inputs(bridge):
    payload = bridge.format_decision_for_compact(sd())
    w = bridge.generate_zk_witness(payload)
    pub = w["public"]
    assert pub["request_id_hash"] == hashlib.sha256(b"req-1").hexdigest()
    assert pub["policy_id"] == "analytics-agent@v1"
    assert pub["decision"] == "deny"
    assert pub["decision_enum"] == 1
    assert pub["decisionHash"] == sd().decision_hash()


def test_witness_private_inputs(bridge):
    w = bridge.generate_zk_witness(bridge.format_decision_for_compact(sd()))
    priv = w["private"]
    assert priv["agent_id"] == "analytics-agent"
    assert priv["fields"] == ["employee.email"]
    assert priv["timestamp"] == FIXED_TS
    assert priv["reason"] == "Matched explicit policy rule"


def test_witness_does_not_leak_raw_identity_into_public(bridge):
    w = bridge.generate_zk_witness(bridge.format_decision_for_compact(sd()))
    pub = w["public"]
    # policy_id is deliberately public; nothing else raw is.
    assert set(pub) == {"request_id_hash", "policy_id", "decision", "decision_enum", "decisionHash"}
    other = " ".join(str(v) for k, v in pub.items() if k != "policy_id")
    assert FIXED_TS not in other                        # timestamp stays private
    assert "employee.email" not in other                # raw field name stays private
    assert "req-1" not in other                         # only its hash is public
    assert pub["request_id_hash"] != "req-1"


def test_witness_is_deterministic(bridge):
    p = bridge.format_decision_for_compact(sd())
    assert bridge.generate_zk_witness(p) == bridge.generate_zk_witness(p)


def test_witness_accepts_security_decision_directly(bridge):
    w = bridge.generate_zk_witness(sd())
    assert w["public"]["decisionHash"] == sd().decision_hash()


# =====================================================================
# export_audit_batch
# =====================================================================

def test_export_writes_valid_json(bridge, tmp_path):
    path = tmp_path / "batch.json"
    returned = bridge.export_audit_batch(path)
    on_disk = json.loads(path.read_text())
    assert on_disk == returned


def test_export_batch_schema(bridge, tmp_path):
    batch = bridge.export_audit_batch(tmp_path / "b.json")
    assert batch["schema"] == MidnightBridge.SCHEMA
    assert batch["contract"] == "policy_attestation.compact"
    assert batch["circuit"] == "recordAttestation"
    assert batch["count"] == 2
    assert len(batch["decisions"]) == 2
    for rec in batch["decisions"]:
        assert set(rec) == {"decision_hash", "compact", "witness"}
        assert rec["compact"]["public"]["decisionHash"] == rec["decision_hash"]


def test_export_state_commitment_is_sha256_over_hashes(bridge, tmp_path):
    batch = bridge.export_audit_batch(tmp_path / "b.json")
    concat = "".join(r["decision_hash"][2:] for r in batch["decisions"])
    assert batch["state_commitment"] == "0x" + hashlib.sha256(concat.encode()).hexdigest()


def test_export_signature_verifies(bridge, tmp_path):
    batch = bridge.export_audit_batch(tmp_path / "b.json")
    assert MidnightBridge.verify_batch(batch, KEY) is True
    assert MidnightBridge.verify_batch(batch, b"wrong-key") is False


def test_export_signature_detects_tampering(bridge, tmp_path):
    batch = bridge.export_audit_batch(tmp_path / "b.json")
    batch["decisions"][0]["decision_hash"] = "0x" + "0" * 64
    assert MidnightBridge.verify_batch(batch, KEY) is False


def test_export_is_reproducible_with_fixed_clock(tmp_path):
    def mk():
        return MidnightBridge([sd(), sd(request_id="req-2")], signing_key=KEY,
                              timestamp_fn=lambda: FIXED_TS)
    a = mk().export_audit_batch(tmp_path / "a.json")
    b = mk().export_audit_batch(tmp_path / "b.json")
    assert a == b


def test_empty_batch_is_valid(tmp_path):
    br = MidnightBridge([], signing_key=KEY, timestamp_fn=lambda: FIXED_TS)
    batch = br.export_audit_batch(tmp_path / "e.json")
    assert batch["count"] == 0
    assert batch["state_commitment"] == "0x" + hashlib.sha256(b"").hexdigest()
    assert MidnightBridge.verify_batch(batch, KEY) is True


# =====================================================================
# integration with the real audit log
# =====================================================================

def test_from_audit_log_end_to_end(tmp_path):
    db = MockEmployeeDB()
    mw = PrivacyFirewallMiddleware.from_policy_file(POLICY_PATH, db)
    agent = AIAgent(mw)
    agent.request_aggregate(["department", "salary"])
    agent.request_read(["email"])

    br = MidnightBridge.from_audit_log(mw.audit_log, signing_key=KEY,
                                      timestamp_fn=lambda: FIXED_TS)
    batch = br.export_audit_batch(tmp_path / "audit.json")

    assert batch["count"] == len(mw.audit_log.entries())
    assert MidnightBridge.verify_batch(batch, KEY)
    # every logged field shows up in a witness private input
    logged = {e.field for e in mw.audit_log.entries()}
    witnessed = {d["witness"]["private"]["fields"][0] for d in batch["decisions"]}
    assert witnessed == logged


def test_security_decision_coerce_from_field_decision():
    from privacy_firewall.policy_engine import FieldDecision
    fd = FieldDecision("analytics-agent", "employee.name", Decision.DENY, "fail closed")
    sec = SecurityDecision.coerce(fd)
    assert sec.agent_id == "analytics-agent"
    assert sec.decision == "deny"
    assert sec.decision_enum == 1
