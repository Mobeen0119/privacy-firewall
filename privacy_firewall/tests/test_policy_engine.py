from pathlib import Path

import pytest

from privacy_firewall import Decision, PolicyEngine

POLICY_PATH = Path(__file__).parent.parent / "policies" / "analytics_agent.yaml"


def test_allow_field_is_allowed():
    engine = PolicyEngine.from_yaml(POLICY_PATH)
    fd = engine.evaluate_field("analytics-agent", "employee.department")
    assert fd.decision is Decision.ALLOW


def test_aggregate_only_field():
    engine = PolicyEngine.from_yaml(POLICY_PATH)
    fd = engine.evaluate_field("analytics-agent", "employee.salary")
    assert fd.decision is Decision.AGGREGATE_ONLY


def test_deny_field():
    engine = PolicyEngine.from_yaml(POLICY_PATH)
    fd = engine.evaluate_field("analytics-agent", "employee.email")
    assert fd.decision is Decision.DENY


def test_unknown_field_fails_closed():
    engine = PolicyEngine.from_yaml(POLICY_PATH)
    fd = engine.evaluate_field("analytics-agent", "employee.social_security_number")
    assert fd.decision is Decision.DENY
    assert "not covered" in fd.reason


def test_unknown_agent_fails_closed():
    engine = PolicyEngine.from_yaml(POLICY_PATH)
    fd = engine.evaluate_field("some-other-agent", "employee.department")
    assert fd.decision is Decision.DENY
    assert "No policy registered" in fd.reason


def test_evaluate_request_preserves_order():
    engine = PolicyEngine.from_yaml(POLICY_PATH)
    fields = ["employee.department", "employee.salary", "employee.name"]
    decisions = engine.evaluate_request("analytics-agent", fields)
    assert [d.field for d in decisions] == fields
    assert [d.decision for d in decisions] == [
        Decision.ALLOW, Decision.AGGREGATE_ONLY, Decision.DENY,
    ]


def test_invalid_decision_string_rejected():
    engine = PolicyEngine()
    with pytest.raises(ValueError):
        engine.register_policy("bad-agent", {"employee.name": "sometimes"})
