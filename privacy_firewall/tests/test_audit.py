from dataclasses import replace

from privacy_firewall import AuditLog, Decision


def test_chain_verifies_when_untouched():
    log = AuditLog()
    log.record("analytics-agent", "employee.department", Decision.ALLOW, "ok")
    log.record("analytics-agent", "employee.email", Decision.DENY, "protected")
    assert log.verify_chain() is True


def test_chain_breaks_if_entry_is_edited():
    log = AuditLog()
    log.record("analytics-agent", "employee.department", Decision.ALLOW, "ok")
    log.record("analytics-agent", "employee.email", Decision.DENY, "protected")

    # Simulate tampering: someone edits a past decision from DENY to ALLOW.
    tampered = replace(log._entries[1], decision=Decision.ALLOW)
    log._entries[1] = tampered

    assert log.verify_chain() is False


def test_chain_breaks_if_entry_removed():
    log = AuditLog()
    log.record("analytics-agent", "employee.department", Decision.ALLOW, "ok")
    log.record("analytics-agent", "employee.email", Decision.DENY, "protected")
    log.record("analytics-agent", "employee.salary", Decision.AGGREGATE_ONLY, "ok")

    del log._entries[1]  # remove the middle entry
    assert log.verify_chain() is False


def test_empty_log_verifies_trivially():
    assert AuditLog().verify_chain() is True
