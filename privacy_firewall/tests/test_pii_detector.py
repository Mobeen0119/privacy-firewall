import pytest

from privacy_firewall.pii_detector import (
    PIIDetector,
    PIIEntity,
    PIIType,
    detect,
    has_pii,
    mask,
)


@pytest.fixture
def d():
    return PIIDetector()


# -- EMAIL -----------------------------------------------------------------

def test_detects_email(d):
    ents = d.detect("ping me at alice.smith+work@example.co.uk please")
    assert [e.type for e in ents] == [PIIType.EMAIL]
    assert ents[0].value == "alice.smith+work@example.co.uk"


def test_email_offsets_are_exact(d):
    text = "from bob@corp.com now"
    e = d.detect(text)[0]
    assert text[e.start:e.end] == e.value == "bob@corp.com"


def test_multiple_emails(d):
    ents = d.detect("a@x.com and b@y.com and c@z.org")
    assert len(ents) == 3
    assert all(e.type is PIIType.EMAIL for e in ents)


# -- PHONE ---------------------------------------------------------------

@pytest.mark.parametrize(
    "phone",
    [
        "(415) 555-0132",
        "415-555-0132",
        "415.555.0132",
        "+1 415 555 0132",
        "+44 20 7946 0958",
    ],
)
def test_detects_phone_formats(d, phone):
    ents = d.detect(f"call {phone} tomorrow")
    assert any(e.type is PIIType.PHONE_NUMBER for e in ents)


def test_bare_10_digit_blob_is_not_phone(d):
    # No separators, no country code -> not confidently a phone number.
    ents = d.detect("order number 4155550132 shipped")
    assert not any(e.type is PIIType.PHONE_NUMBER for e in ents)


# -- SSN ----------------------------------------------------------------

def test_detects_ssn(d):
    e = d.detect("SSN: 123-45-6789")[0]
    assert e.type is PIIType.SSN
    assert e.value == "123-45-6789"


def test_invalid_ssn_prefixes_rejected(d):
    assert not has_pii("000-12-3456")
    assert not d.detect("666-12-3456")
    assert not d.detect("123-00-4567")
    assert not d.detect("123-45-0000")


def test_ssn_not_reported_as_phone(d):
    ents = d.detect("id 123-45-6789")
    assert [e.type for e in ents] == [PIIType.SSN]


# -- API KEY / SECRETS -------------------------------------------------

def test_detects_prefixed_api_key(d):
    e = d.detect("key=MOCK_API_KEY_99887766554433221100aabbccddeeff")[0]
    assert e.type is PIIType.API_KEY
    assert e.value.startswith("MOCK_API_KEY_")


def test_detects_uuid_as_secret(d):
    ents = d.detect("token 550e8400-e29b-41d4-a716-446655440000")
    assert [e.type for e in ents] == [PIIType.API_KEY]


def test_detects_labelled_secrets(d):
    assert has_pii("ACCESS_KEY_A1B2C3D4E5F6G7H8I9")
    assert has_pii("MOCK_SECRET_KEY_0011223344556677")
    assert has_pii("TEST_SECRET_KEY_abc123xyz789")


def test_detects_high_entropy_token(d):
    secret = "Zx9Kq2Lp7Vn4Rt8Wm3Yb6Hd1Gf5Jc0"
    ents = d.detect(f"bearer {secret}")
    assert any(e.type is PIIType.API_KEY and e.value == secret for e in ents)


def test_low_entropy_long_word_is_not_a_secret(d):
    assert not has_pii("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert not has_pii("thisisjustalonglowercasesentencewithoutdigits")


# -- CREDIT CARD -----------------------------------------------------

def test_detects_luhn_valid_card(d):
    e = d.detect("card 4242 4242 4242 4242 exp 12/29")[0]
    assert e.type is PIIType.CREDIT_CARD


def test_detects_card_with_dashes(d):
    ents = d.detect("4111-1111-1111-1111")
    assert [e.type for e in ents] == [PIIType.CREDIT_CARD]


def test_luhn_invalid_number_rejected(d):
    assert not has_pii("4242 4242 4242 4243")


# -- PERSON NAME ---------------------------------------------------

def test_detects_two_word_name(d):
    ents = d.detect("Please contact Alice Johnson about the ticket")
    assert any(e.type is PIIType.PERSON_NAME and e.value == "Alice Johnson" for e in ents)


def test_detects_titled_name_including_title(d):
    ents = d.detect("Reviewed by Dr. Emily Carter yesterday")
    name = next(e for e in ents if e.type is PIIType.PERSON_NAME)
    assert name.value == "Dr. Emily Carter"


def test_place_names_not_flagged_as_person(d):
    ents = d.detect("The office in New York opened Monday")
    assert not any(e.type is PIIType.PERSON_NAME for e in ents)


# -- has_pii / empty ---------------------------------------------

def test_has_pii_true_and_false(d):
    assert d.has_pii("mail me at x@y.com")
    assert not d.has_pii("nothing sensitive in this sentence at all")


def test_empty_text(d):
    assert d.detect("") == []
    assert d.mask("") == ""
    assert d.has_pii("") is False


# -- MASKING -----------------------------------------------------

def test_mask_redact_strategy(d):
    out = d.mask("email x@y.com and ssn 123-45-6789", strategy="redact")
    assert out == "email [REDACTED_EMAIL] and ssn [REDACTED_SSN]"


def test_mask_token_strategy_is_stable_for_equal_values(d):
    out = d.mask("from a@x.com to a@x.com cc b@x.com", strategy="token")
    assert out == "from EMAIL_001 to EMAIL_001 cc EMAIL_002"


def test_mask_hash_strategy_is_deterministic(d):
    text = "reach me: dana@corp.com"
    first = d.mask(text, strategy="hash")
    second = d.mask(text, strategy="hash")
    assert first == second
    assert "dana@corp.com" not in first
    assert first.startswith("reach me: EMAIL_")


def test_mask_leaves_clean_text_untouched(d):
    text = "just a normal log line, status ok"
    assert d.mask(text) == text


def test_mask_unknown_strategy_raises(d):
    with pytest.raises(ValueError):
        d.mask("x@y.com", strategy="bogus")


def test_mask_does_not_shift_and_drop_spans(d):
    text = "contacts: alice@a.com, bob@b.com, carol@c.com"
    out = d.mask(text, strategy="redact")
    assert out.count("[REDACTED_EMAIL]") == 3
    assert "@" not in out


# -- overlap resolution ---------------------------------------

def test_credit_card_wins_over_name_or_phone(d):
    # 16-digit Luhn-valid card written with spaces should be one CC span.
    ents = d.detect("pay 4242 4242 4242 4242")
    cc = [e for e in ents if e.type is PIIType.CREDIT_CARD]
    assert len(cc) == 1
    assert not any(e.type is PIIType.PHONE_NUMBER for e in ents)


def test_detected_spans_never_overlap(d):
    text = "Dr. Alice Johnson a@x.com 123-45-6789 SECRET_KEY_ABCDEFGHIJ1234567890 4242424242424242"
    ents = d.detect(text)
    ents.sort(key=lambda e: e.start)
    for prev, cur in zip(ents, ents[1:]):
        assert prev.end <= cur.start


# -- module-level helpers ------------------------------------

def test_module_level_functions_match_default_instance():
    text = "call (212) 555-0199 or mail sam@aol.com"
    assert has_pii(text) is True
    assert {e.type for e in detect(text)} == {PIIType.PHONE_NUMBER, PIIType.EMAIL}
    assert "sam@aol.com" not in mask(text, strategy="redact")


def test_pii_entity_len_matches_span():
    e = PIIEntity(PIIType.EMAIL, "a@b.com", 5, 12)
    assert len(e) == 7
