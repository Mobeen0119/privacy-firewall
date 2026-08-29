from pathlib import Path

import pytest

from privacy_firewall import DataMinimizer, PolicyEngine, PolicyViolation

POLICY_PATH = Path(__file__).parent.parent / "policies" / "analytics_agent.yaml"

EMPLOYEES = [
    {"name": "Alice", "email": "alice@company.com", "department": "Engineering", "salary": 90000},
    {"name": "Bob", "email": "bob@company.com", "department": "Engineering", "salary": 85000},
    {"name": "Sarah", "email": "sarah@company.com", "department": "HR", "salary": 62000},
]


def engineering_only(records):
    return [r for r in records if r["department"] == "Engineering"]


@pytest.fixture
def minimizer():
    engine = PolicyEngine.from_yaml(POLICY_PATH)
    return DataMinimizer(engine)


def test_demo_1_average_salary_never_exposes_raw_values(minimizer):
    """'What is the average salary in Engineering?' should return 87500
    and must never leak the individual 90000 / 85000 figures or names."""
    records = engineering_only(EMPLOYEES)
    result = minimizer.minimize(
        agent="analytics-agent",
        records=records,
        requested_fields=["employee.department", "employee.salary"],
    )
    assert result.aggregates["employee.salary"]["avg"] == 87500.0
    assert result.allowed_fields["employee.department"] == ["Engineering", "Engineering"]
    assert "employee.name" not in result.allowed_fields
    assert "employee.email" not in result.allowed_fields


def test_demo_2_names_and_emails_are_denied(minimizer):
    """'Give me the names and emails of all Engineering employees.'
    Both fields must come back denied, and no values returned."""
    records = engineering_only(EMPLOYEES)
    result = minimizer.minimize(
        agent="analytics-agent",
        records=records,
        requested_fields=["employee.name", "employee.email"],
    )
    assert result.is_denied("employee.name")
    assert result.is_denied("employee.email")
    assert result.allowed_fields == {}
    assert result.aggregates == {}


def test_mixed_request_partitions_correctly(minimizer):
    records = engineering_only(EMPLOYEES)
    result = minimizer.minimize(
        agent="analytics-agent",
        records=records,
        requested_fields=["employee.department", "employee.salary", "employee.name"],
    )
    assert "employee.department" in result.allowed_fields
    assert "employee.salary" in result.aggregates
    assert "employee.name" in result.denied_fields


def test_require_raw_raises_for_aggregate_only_field(minimizer):
    with pytest.raises(PolicyViolation):
        minimizer.require_raw("analytics-agent", "employee.salary")


def test_require_raw_raises_for_denied_field(minimizer):
    with pytest.raises(PolicyViolation):
        minimizer.require_raw("analytics-agent", "employee.email")


def test_require_raw_succeeds_for_allowed_field(minimizer):
    minimizer.require_raw("analytics-agent", "employee.department")  # should not raise


def test_every_decision_is_audited(minimizer):
    minimizer.minimize(
        agent="analytics-agent",
        records=EMPLOYEES,
        requested_fields=["employee.department", "employee.salary", "employee.email"],
    )
    logged_fields = {entry.field for entry in minimizer.audit_log.entries()}
    assert logged_fields == {"employee.department", "employee.salary", "employee.email"}
