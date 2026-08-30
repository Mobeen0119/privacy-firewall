"""Generates a demo audit log with ALLOW/DENY/AGGREGATE_ONLY decisions."""

import json
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path(__file__).parent / "audit_log.jsonl"

AGENTS = ["analytics-agent", "support-agent", "reporting-agent"]
RESOURCES = ["employee.email", "employee.salary", "employee.department", "employee.name", "employee.phone"]
DECISIONS = ["ALLOW", "DENY", "AGGREGATE_ONLY"]


def generate_record() -> dict:
    return {
        "request_id": str(uuid.uuid4()),
        "agent": random.choice(AGENTS),
        "resource": random.choice(RESOURCES),
        "decision": random.choice(DECISIONS),
        "policy": "P-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    count = 10
    with open(LOG_FILE, "w") as f:
        for _ in range(count):
            f.write(json.dumps(generate_record()) + "\n")
    print(f"Wrote {count} records to {LOG_FILE}")
