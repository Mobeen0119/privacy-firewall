"""Runnable demo of the policy engine + data minimizer + audit log.

Reproduces Demo 1, Demo 2, and Demo 5 from the project README using
the same fake employee database and analytics-agent policy.

Run with: python demo.py
"""

from pathlib import Path

from privacy_firewall import DataMinimizer, PolicyEngine

POLICY_PATH = Path(__file__).parent / "policies" / "analytics_agent.yaml"

EMPLOYEES = [
    {"name": "Alice", "email": "alice@company.com", "department": "Engineering", "salary": 90000},
    {"name": "Bob", "email": "bob@company.com", "department": "Engineering", "salary": 85000},
    {"name": "Sarah", "email": "sarah@company.com", "department": "HR", "salary": 62000},
]


def divider(title: str) -> None:
    print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")


def demo_1_normal_request(minimizer: DataMinimizer) -> None:
    divider("Demo 1 — Normal request: average Engineering salary")
    engineering = [e for e in EMPLOYEES if e["department"] == "Engineering"]
    result = minimizer.minimize(
        agent="analytics-agent",
        records=engineering,
        requested_fields=["employee.department", "employee.salary"],
    )
    avg = result.aggregates["employee.salary"]["avg"]
    print(f"Firewall decision: ALLOWED (salary field returned as aggregate only)")
    print(f"AI response to user: Average Engineering salary: ${avg:,.0f}")
    print(f"Raw values ever seen by the LLM: NONE (only the aggregate above)")


def demo_2_unauthorized_request(minimizer: DataMinimizer) -> None:
    divider("Demo 2 — Unauthorized request: names and emails")
    result = minimizer.minimize(
        agent="analytics-agent",
        records=EMPLOYEES,
        requested_fields=["employee.name", "employee.email"],
    )
    print("Firewall decision: BLOCKED")
    for denied_field in result.denied_fields:
        print(f"  {denied_field} -> DENY")
    print("Reason: Protected personal data")


def demo_5_verification(minimizer: DataMinimizer) -> None:
    divider("Demo 5 — Verification")
    print(f"Audit entries recorded so far: {len(minimizer.audit_log.entries())}")
    for entry in minimizer.audit_log.entries():
        print(f"  [{entry.timestamp}] {entry.agent} -> {entry.field}: {entry.decision.value}")
    intact = minimizer.audit_log.verify_chain()
    print(f"\nIndependent verification of audit chain: {'PASSED' if intact else 'FAILED'}")


def main() -> None:
    engine = PolicyEngine.from_yaml(POLICY_PATH)
    minimizer = DataMinimizer(engine)

    demo_1_normal_request(minimizer)
    demo_2_unauthorized_request(minimizer)
    demo_5_verification(minimizer)


if __name__ == "__main__":
    main()
