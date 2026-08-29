import pytest

from privacy_firewall.pii_detector import PIIDetector
from privacy_firewall.output_firewall import (
    ALLOW,
    BLOCK,
    OutputDecision,
    OutputFirewall,
    OutputViolation,
)

CANARIES = ["CANARY-SECRET-abc123", "CANARY-SECRET-deadbeef"]


@pytest.fixture
def fw():
    return OutputFirewall(PIIDetector(), canary_tokens=CANARIES)


# -- clean output --------------------------------------------------------

def test_clean_text_is_allowed(fw):
    d = fw.inspect_response("The average salary in Engineering is 87500.")
    assert d.decision == ALLOW
    assert d.is_allowed
    assert d.output == "The average salary in Engineering is 87500."
    assert d.violations == []


def test_clean_text_output_passed_through_unchanged(fw):
    raw = "Engineering has 2 employees. No further detail available."
    assert fw.inspect_response(raw).output is raw


def test_empty_output_is_allowed(fw):
    d = fw.inspect_response("")
    assert d.decision == ALLOW


def test_none_output_is_allowed(fw):
    d = fw.inspect_response(None)
    assert d.decision == ALLOW
    assert d.output is None


def test_aggregate_style_answer_with_numbers_not_flagged(fw):
    d = fw.inspect_response("count=3 sum=237000 avg=79000 min=62000 max=90000")
    assert d.decision == ALLOW


# -- canary leaks -----------------------------------------------------

def test_canary_leak_is_blocked(fw):
    d = fw.inspect_response("Sure, here is the record: CANARY-SECRET-abc123 belongs to row 4")
    assert d.decision == BLOCK
    assert d.is_blocked
    assert d.output is None
    assert d.reason.startswith("Data leakage detected:")
    assert "CANARY-SECRET-abc123" in d.reason


def test_canary_leak_violation_kind(fw):
    d = fw.inspect_response("leaked CANARY-SECRET-deadbeef here")
    assert [v.kind for v in d.violations] == ["canary"]


def test_second_registered_canary_also_caught(fw):
    d = fw.inspect_response("CANARY-SECRET-deadbeef")
    assert d.is_blocked


def test_unregistered_canary_like_string_is_not_blocked(fw):
    d = fw.inspect_response("CANARY-SECRET-not-registered")
    assert d.decision == ALLOW


def test_register_canary_at_runtime(fw):
    fw.register_canary("CANARY-SECRET-newone")
    d = fw.inspect_response("oops CANARY-SECRET-newone")
    assert d.is_blocked
    assert "CANARY-SECRET-newone" in fw.canary_tokens


def test_firewall_with_no_canaries_still_checks_pii():
    fw = OutputFirewall(PIIDetector())
    assert fw.canary_tokens == []
    assert fw.inspect_response("mail me at x@y.com").is_blocked


# -- PII leaks ------------------------------------------------------

def test_email_leak_is_blocked(fw):
    d = fw.inspect_response("You can reach Alice at alice@company.com")
    assert d.decision == BLOCK
    assert any(v.kind == "pii" for v in d.violations)
    assert "alice@company.com" in d.reason


def test_phone_leak_is_blocked(fw):
    d = fw.inspect_response("Her direct line is (415) 555-0132.")
    assert d.is_blocked


def test_credential_leak_is_blocked(fw):
    d = fw.inspect_response("the api key is MOCK_API_KEY_99887766554433221100aabbccddeeff")
    assert d.is_blocked
    assert "API_KEY" in d.reason


def test_ssn_leak_is_blocked(fw):
    assert fw.inspect_response("SSN on file: 123-45-6789").is_blocked


def test_credit_card_leak_is_blocked(fw):
    assert fw.inspect_response("card 4242 4242 4242 4242").is_blocked


def test_person_name_leak_is_blocked_by_default(fw):
    d = fw.inspect_response("The top earner is Alice Johnson.")
    assert d.is_blocked
    assert "PERSON_NAME" in d.reason


# -- allowed_fields authorisation --------------------------------

def test_allowed_field_permits_matching_pii(fw):
    d = fw.inspect_response(
        "Contact: alice@company.com",
        allowed_fields=["employee.email"],
    )
    assert d.decision == ALLOW
    assert d.output == "Contact: alice@company.com"


def test_allowed_field_is_type_specific(fw):
    # email authorised, but a phone number still leaks
    d = fw.inspect_response(
        "alice@company.com / (415) 555-0132",
        allowed_fields=["employee.email"],
    )
    assert d.is_blocked
    assert all("PHONE_NUMBER" in v.detail for v in d.violations)


def test_allowed_field_bare_name_also_works(fw):
    d = fw.inspect_response("Alice Johnson", allowed_fields=["name"])
    assert d.decision == ALLOW


def test_credentials_never_authorised_even_if_listed(fw):
    d = fw.inspect_response(
        "key MOCK_API_KEY_99887766554433221100aabbccddeeff",
        allowed_fields=["api_key", "secret", "employee.api_key"],
    )
    assert d.is_blocked


def test_canary_blocks_even_when_fields_allowed(fw):
    d = fw.inspect_response(
        "alice@company.com CANARY-SECRET-abc123",
        allowed_fields=["employee.email"],
    )
    assert d.is_blocked
    assert any(v.kind == "canary" for v in d.violations)


# -- combined / reporting -------------------------------------

def test_multiple_violations_all_reported(fw):
    d = fw.inspect_response(
        "Alice Johnson alice@company.com CANARY-SECRET-abc123"
    )
    kinds = {v.kind for v in d.violations}
    assert kinds == {"pii", "canary"}
    assert d.reason.count(";") >= 1


def test_registry_object_with_tokens_method_is_accepted():
    class Registry:
        def tokens(self):
            return ["CANARY-SECRET-xyz"]

    fw = OutputFirewall(PIIDetector(), canary_tokens=Registry())
    assert fw.inspect_response("CANARY-SECRET-xyz").is_blocked


def test_output_decision_flags_are_consistent(fw):
    allow = fw.inspect_response("all clear")
    block = fw.inspect_response("CANARY-SECRET-abc123")
    assert allow.is_allowed and not allow.is_blocked
    assert block.is_blocked and not block.is_allowed


# -- obfuscated / encoded canary evasion --------------------------------

import base64 as _b64

_CANARY = "CANARY-SECRET-abc123"


@pytest.fixture
def cfw():
    return OutputFirewall(PIIDetector(), canary_tokens=[_CANARY])


def test_canary_newline_split_is_caught(cfw):
    d = cfw.inspect_response("here is the ref: CANARY-SECRET-\nabc123 -- done")
    assert d.is_blocked
    assert any(v.kind == "canary" for v in d.violations)
    assert "whitespace-obfuscated" in d.reason


def test_canary_space_between_every_char_is_caught(cfw):
    d = cfw.inspect_response("C A N A R Y - S E C R E T - a b c 1 2 3")
    assert d.is_blocked
    assert any(v.kind == "canary" for v in d.violations)


def test_canary_interior_space_is_caught(cfw):
    assert cfw.inspect_response("token = CANARY-SECRET- abc123").is_blocked


def test_canary_base64_std_is_caught(cfw):
    blob = _b64.b64encode(_CANARY.encode()).decode()
    d = cfw.inspect_response(f"the encoded reference is {blob}")
    assert d.is_blocked
    assert any(v.kind == "canary" and "base64-encoded" in v.detail for v in d.violations)


def test_canary_base64_urlsafe_is_caught(cfw):
    blob = _b64.urlsafe_b64encode(_CANARY.encode()).decode()
    assert cfw.inspect_response(f"ref: {blob}").is_blocked


def test_canary_reported_once_per_token(cfw):
    d = cfw.inspect_response(f"{_CANARY} and also CANARY-SECRET-\nabc123")
    canary_hits = [v for v in d.violations if v.kind == "canary"]
    assert len(canary_hits) == 1


def test_words_canary_and_secret_alone_do_not_false_positive(cfw):
    text = "We use canary tokens and secret rotation as part of security testing."
    assert cfw.inspect_response(text).is_allowed


def test_clean_multiline_output_is_allowed(cfw):
    text = "Summary:\n- 5 records\n- avg 80800\n- no personal data returned\n"
    assert cfw.inspect_response(text).is_allowed


def test_empty_and_none_canary_scan_is_safe(cfw):
    assert cfw.inspect_response("").is_allowed
    assert cfw.inspect_response(None).is_allowed
