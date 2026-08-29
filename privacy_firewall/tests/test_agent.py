from pathlib import Path

import pytest

from privacy_firewall import AuditLog
from privacy_firewall.agent import (
    AGGREGATE,
    ALLOW,
    CANARY_TOKENS,
    DENY,
    READ,
    AIAgent,
    FirewallResponse,
    MockEmployeeDB,
    PrivacyFirewallMiddleware,
)

POLICY_PATH = Path(__file__).parent.parent / "policies" / "analytics_agent.yaml"


@pytest.fixture
def db():
    return MockEmployeeDB()


@pytest.fixture
def middleware(db):
    return PrivacyFirewallMiddleware.from_policy_file(POLICY_PATH, db)


@pytest.fixture
def agent(middleware):
    return AIAgent(middleware)


# -- MockEmployeeDB ------------------------------------------------------

def test_db_rows_have_all_fields(db):
    for row in db.records():
        assert set(row) == set(MockEmployeeDB.FIELDS)


def test_db_notes_carry_canary_tokens(db):
    notes_blob = " ".join(r["notes"] for r in db.records())
    assert any(tok in notes_blob for tok in CANARY_TOKENS)


def test_db_records_returns_a_copy(db):
    rows = db.records()
    rows[0]["salary"] = 0
    assert db.records()[0]["salary"] != 0


def test_db_unknown_resource_raises(db):
    with pytest.raises(KeyError):
        db.records("payroll")


# -- AIAgent ---------------------------------------------------------

def test_agent_builds_structured_request(agent):
    req = agent.build_request(AGGREGATE, ["salary", "department"], query="avg salary?")
    assert req == {
        "agent_id": "analytics-agent",
        "resource": "employees",
        "operation": "aggregate",
        "fields": ["salary", "department"],
        "query": "avg salary?",
    }


def test_agent_has_no_database_reference(agent):
    assert not any(isinstance(v, MockEmployeeDB) for v in vars(agent).values())


def test_agent_direct_db_read_is_refused(agent):
    with pytest.raises(PermissionError):
        agent.read_database()


# -- aggregate path ------------------------------------------------

def test_aggregate_salary_returns_only_aggregates(agent):
    resp = agent.request_aggregate(["department", "salary"], query="avg salary")
    assert resp.decision == ALLOW
    assert resp.is_allowed
    agg = resp.payload["aggregates"]["salary"]
    assert agg["avg"] == 80800.0
    assert agg["count"] == 5
    # raw salary values never surface
    assert "salary" not in resp.payload["allowed_fields"]
    assert "name" not in resp.payload["allowed_fields"]
    assert "email" not in resp.payload["allowed_fields"]


def test_aggregate_allowed_field_passes_through(agent):
    resp = agent.request_aggregate(["department", "salary"])
    assert resp.payload["allowed_fields"]["department"].count("Engineering") == 3


def test_aggregate_of_denied_fields_only_is_denied(agent):
    resp = agent.request_aggregate(["name", "email"])
    assert resp.decision == DENY
    assert resp.payload is None
    assert set(resp.denied_fields) == {"name", "email"}


# -- read path --------------------------------------------------

def test_read_allowed_field_returns_sanitized_rows(agent):
    resp = agent.request_read(["department"])
    assert resp.decision == ALLOW
    assert resp.denied_fields == []
    assert {r["department"] for r in resp.payload["records"]} == {
        "Engineering", "HR", "Sales",
    }
    for r in resp.payload["records"]:
        assert set(r) == {"department"}


def test_read_denied_fields_blocked(agent):
    resp = agent.request_read(["name", "email"])
    assert resp.decision == DENY
    assert resp.payload is None
    assert set(resp.denied_fields) == {"name", "email"}


def test_read_mixed_request_returns_allowed_only(agent):
    resp = agent.request_read(["department", "name"])
    assert resp.decision == ALLOW
    assert resp.denied_fields == ["name"]
    for r in resp.payload["records"]:
        assert set(r) == {"department"}


def test_read_of_aggregate_only_field_is_denied_for_raw(agent):
    resp = agent.request_read(["salary"])
    assert resp.decision == DENY
    assert resp.denied_fields == ["salary"]


def test_uncovered_field_fails_closed(agent):
    # 'bonus' has no rule of any kind in analytics_agent.yaml.
    resp = agent.request_read(["bonus"])
    assert resp.decision == DENY
    assert resp.denied_fields == ["bonus"]
    assert resp.payload is None


def test_notes_field_is_explicitly_denied(agent):
    # 'notes' now has an explicit `read: deny` rule (schema alignment).
    resp = agent.request_read(["notes"])
    assert resp.decision == DENY
    assert resp.denied_fields == ["notes"]


def test_read_payload_exposes_only_allowed_field_values(agent):
    # Request every column; only the single ALLOW field may come back,
    # and no raw non-allowed value or canary may appear anywhere.
    resp = agent.request_read(list(MockEmployeeDB.FIELDS))
    assert resp.is_allowed
    assert resp.payload["returned_fields"] == ["department"]
    for row in resp.payload["records"]:
        assert set(row) == {"department"}
    blob = repr(resp)
    for leak in ("@company.com", "Alice Johnson", "555-01", "90000", "CANARY-SECRET-"):
        assert leak not in blob


def test_read_path_routes_through_the_minimizer(middleware, agent):
    calls = []
    real = middleware.minimizer.minimize

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return real(*args, **kwargs)

    middleware.minimizer.minimize = spy
    agent.request_read(["department", "name"])
    assert len(calls) == 1  # the read path delegates classification to minimize()


# -- no leakage --------------------------------------------------

def test_no_canary_token_in_any_allowed_payload(agent):
    for resp in (
        agent.request_aggregate(["department", "salary"]),
        agent.request_read(["department"]),
        agent.request_read(["department", "name"]),
    ):
        blob = repr(resp.payload)
        assert all(tok not in blob for tok in CANARY_TOKENS)


def test_denied_read_never_returns_raw_pii(agent):
    resp = agent.request_read(["name", "email", "phone"])
    assert resp.payload is None
    assert "alice@company.com" not in repr(resp)


# -- audit -----------------------------------------------------

def test_every_field_decision_is_audited(middleware, agent):
    agent.request_aggregate(["department", "salary", "email"])
    logged = {e.field for e in middleware.audit_log.entries()}
    assert logged == {"employee.department", "employee.salary", "employee.email"}


def test_audit_chain_stays_intact_across_requests(middleware, agent):
    agent.request_aggregate(["department", "salary"])
    agent.request_read(["name"])
    agent.request_read(["department"])
    assert middleware.audit_log.verify_chain() is True


def test_response_carries_audit_ref(agent):
    resp = agent.request_read(["department"])
    assert isinstance(resp.audit_ref, str) and len(resp.audit_ref) == 64


def test_injected_audit_log_is_used(db):
    shared = AuditLog()
    mw = PrivacyFirewallMiddleware.from_policy_file(POLICY_PATH, db)
    mw = PrivacyFirewallMiddleware(mw.policy_engine, db, audit_log=shared)
    AIAgent(mw).request_read(["department"])
    assert len(shared.entries()) == 1


# -- request validation --------------------------------------

def test_missing_key_raises(middleware):
    with pytest.raises(ValueError):
        middleware.handle_request({"agent_id": "analytics-agent", "resource": "employees"})


def test_bad_operation_raises(middleware):
    with pytest.raises(ValueError):
        middleware.handle_request({
            "agent_id": "analytics-agent", "resource": "employees",
            "operation": "delete", "fields": ["department"],
        })


def test_empty_fields_raises(middleware):
    with pytest.raises(ValueError):
        middleware.handle_request({
            "agent_id": "analytics-agent", "resource": "employees",
            "operation": "read", "fields": [],
        })


def test_unknown_resource_raises(middleware):
    with pytest.raises(ValueError):
        middleware.handle_request({
            "agent_id": "analytics-agent", "resource": "salaries",
            "operation": "read", "fields": ["department"],
        })


def test_unregistered_agent_fails_closed(middleware):
    req = {
        "agent_id": "rogue-agent", "resource": "employees",
        "operation": "read", "fields": ["department"],
    }
    resp = middleware.handle_request(req)
    assert resp.decision == DENY
