"""pytest suite for the audit layer (audit finding M-16).

Covers: known-answer chain vectors, determinism, tamper mutations
(byte flip / key reorder / whitespace), empty-log rejection, corrupt /
wrong-context signature rejection, fail-closed verification, and the
key-generation no-clobber guard.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import sign
from hash_chain import (
    EmptyLogError,
    build_chain,
    build_chain_from_records,
    build_chain_streaming,
    load_lines,
)
from sign import (
    build_commit_message,
    generate_keypair,
    sign_commit,
    verify_commit_signature,
    verify_signature,
)

REC_A = b'{"a":1,"b":"x"}'
REC_B = b'{"a":2,"b":"y"}'


# --------------------------------------------------------------------- chain

def test_kat_single_and_multi_record():
    _, root1 = build_chain([REC_A])
    _, root2 = build_chain([REC_A, REC_B])
    assert len(root1) == 64 and len(root2) == 64
    assert root1 != root2
    # explicit KAT: recompute the first step by hand
    import hashlib

    expect = hashlib.sha256(
        (b"\x00" * 32) + b"\x1f" + len(REC_A).to_bytes(8, "big") + REC_A
    ).hexdigest()
    assert root1 == expect


def test_chain_is_deterministic():
    a = build_chain([REC_A, REC_B])[1]
    b = build_chain([REC_A, REC_B])[1]
    assert a == b


def test_tamper_byte_flip_changes_root():
    """Flip a byte inside a JSON string value (stays valid JSON) -> new root."""
    base = build_chain([REC_A, REC_B])[1]
    mutated = REC_B.replace(b'"y"', b'"z"')
    assert mutated != REC_B
    assert build_chain([REC_A, mutated])[1] != base


def test_tamper_key_reorder_changes_root():
    """Cosmetic-only re-serialization must NOT round-trip (H-3 regression)."""
    original = b'{"a":1,"b":2}'
    reordered = b'{"b":2,"a":1}'
    assert json.loads(original) == json.loads(reordered)
    assert build_chain([original])[1] != build_chain([reordered])[1]


def test_tamper_whitespace_changes_root():
    assert build_chain([b'{"a":1}'])[1] != build_chain([b'{"a": 1}'])[1]


def test_duplicate_keys_rejected():
    with pytest.raises(ValueError):
        build_chain([b'{"a":1,"a":2}'])


def test_non_finite_json_rejected():
    with pytest.raises(ValueError):
        build_chain([b'{"a":NaN}'])


# ---------------------------------------------------------------- empty log

def test_build_chain_empty_list_rejected():
    with pytest.raises(EmptyLogError):
        build_chain([])
    with pytest.raises(EmptyLogError):
        build_chain_from_records([])


def test_load_lines_missing_file(tmp_path):
    with pytest.raises(EmptyLogError):
        load_lines(tmp_path / "nope.jsonl")


def test_load_lines_whitespace_only(tmp_path):
    p = tmp_path / "ws.jsonl"
    p.write_text("   \n\n\t\n")
    with pytest.raises(EmptyLogError):
        load_lines(p)


# ------------------------------------------------------- streaming / L-11 / L-3

def test_streaming_root_matches_in_memory(tmp_path):
    p = tmp_path / "audit_log.jsonl"
    p.write_bytes(REC_A + b"\n" + REC_B + b"\n")
    count, root = build_chain_streaming(p)
    assert count == 2
    assert root == build_chain(load_lines(p))[1]


def test_line_numbered_parse_error(tmp_path):
    p = tmp_path / "audit_log.jsonl"
    p.write_bytes(REC_A + b"\n" + b'{"a": bad}\n')
    with pytest.raises(ValueError, match=r"line 2:"):
        build_chain_streaming(p)


def test_salt_changes_root_and_is_deterministic():
    salt = b"\x11" * 16
    plain = build_chain([REC_A, REC_B])[1]
    salted = build_chain([REC_A, REC_B], salt=salt)[1]
    assert salted != plain
    assert salted == build_chain([REC_A, REC_B], salt=salt)[1]
    assert build_chain([REC_A, REC_B], salt=b"\x22" * 16)[1] != salted


# ------------------------------------------------------------------ signing

@pytest.fixture()
def keypair(tmp_path, monkeypatch):
    priv = tmp_path / "k.pem"
    pub = tmp_path / "k.pub.pem"
    monkeypatch.delenv("FIREWALL_KEY_PASSPHRASE", raising=False)
    generate_keypair(priv, pub)
    monkeypatch.setattr(sign, "PRIVATE_KEY_PATH", priv)
    monkeypatch.setattr(sign, "PUBLIC_KEY_PATH", pub)
    return priv, pub


ROOT = "11" * 32
CTX = ("preview", "0200abcd", 7)


def test_context_bound_roundtrip(keypair):
    priv, pub = keypair
    sig = sign_commit(ROOT, *CTX, private_key_path=priv)
    assert verify_commit_signature(ROOT, sig, *CTX, verify_key_path=pub) is True


def test_signature_bit_flip_rejected(keypair):
    priv, pub = keypair
    sig = bytearray.fromhex(sign_commit(ROOT, *CTX, private_key_path=priv))
    sig[0] ^= 0x01
    assert verify_commit_signature(ROOT, sig.hex(), *CTX, verify_key_path=pub) is False


@pytest.mark.parametrize(
    "bad_ctx",
    [("testnet", "0200abcd", 7), ("preview", "0200dead", 7), ("preview", "0200abcd", 8)],
)
def test_wrong_context_rejected(keypair, bad_ctx):
    priv, pub = keypair
    sig = sign_commit(ROOT, *CTX, private_key_path=priv)
    assert verify_commit_signature(ROOT, sig, *bad_ctx, verify_key_path=pub) is False


def test_verify_fails_closed_on_garbage(keypair):
    _, pub = keypair
    msg = build_commit_message(ROOT, *CTX)
    assert verify_signature(msg, "zzzz", pub) is False          # non-hex
    assert verify_signature(msg, "abc", pub) is False           # odd length
    assert verify_signature(msg, "", pub) is False              # empty
    assert verify_signature(msg, "aa", Path("/no/such.pem")) is False  # missing key


def test_zero_root_rejected(keypair):
    priv, _ = keypair
    with pytest.raises(ValueError):
        sign_commit("0" * 64, *CTX, private_key_path=priv)


def test_generate_keypair_no_clobber(tmp_path, monkeypatch):
    monkeypatch.delenv("FIREWALL_KEY_PASSPHRASE", raising=False)
    priv = tmp_path / "k.pem"
    pub = tmp_path / "k.pub.pem"
    generate_keypair(priv, pub)
    with pytest.raises(SystemExit):
        generate_keypair(priv, pub)
    generate_keypair(priv, pub, overwrite=True)  # --force path


def test_encrypted_key_roundtrip(tmp_path, monkeypatch):
    priv = tmp_path / "enc.pem"
    pub = tmp_path / "enc.pub.pem"
    monkeypatch.setenv("FIREWALL_KEY_PASSPHRASE", "correct horse battery staple")
    generate_keypair(priv, pub)
    assert b"ENCRYPTED PRIVATE KEY" in priv.read_bytes()
    sig = sign_commit(ROOT, *CTX, private_key_path=priv)
    assert verify_commit_signature(ROOT, sig, *CTX, verify_key_path=pub) is True


# ------------------------------------------------------- end-to-end via CLI

def test_verify_cli_pass_and_tamper(tmp_path, monkeypatch):
    log = tmp_path / "audit_log.jsonl"
    log.write_bytes(REC_A + b"\n" + REC_B + b"\n")
    _, root = build_chain(load_lines(log))

    priv = tmp_path / "k.pem"
    pub = tmp_path / "k.pub.pem"
    monkeypatch.delenv("FIREWALL_KEY_PASSPHRASE", raising=False)
    generate_keypair(priv, pub)
    sig = sign_commit(root, "preview", "0200abcd", 3, private_key_path=priv)

    import verify as verify_mod

    assert verify_mod.verify_log(
        str(log), root, sig, "preview", "0200abcd", 3, onchain_root=root,
        verify_key_path=pub,
    ) is True
    # cosmetic-only edit on disk -> chain mismatch -> FAIL
    log.write_bytes(REC_A.replace(b'"x"', b'"x" ') + b"\n" + REC_B + b"\n")
    assert verify_mod.verify_log(
        str(log), root, sig, "preview", "0200abcd", 3, onchain_root=root,
        verify_key_path=pub,
    ) is False
    # on-chain mismatch alone -> FAIL
    log.write_bytes(REC_A + b"\n" + REC_B + b"\n")
    assert verify_mod.verify_log(
        str(log), root, sig, "preview", "0200abcd", 3, onchain_root="ab" * 32,
        verify_key_path=pub,
    ) is False
