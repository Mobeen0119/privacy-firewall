"""Builds a tamper-evident hash chain over an audit log (JSONL) and writes the root hash.

Canonicalization + domain separation (audit finding H-3):

  - The chain is computed over the RAW on-disk bytes of each log line, so
    a re-serialization that normalizes whitespace / key order / number
    spelling no longer round-trips to the same hash.
  - Each step is length-prefixed and delimited:

        h_{n+1} = SHA256( [salt] || h_n || 0x1f || len(raw_line) BE8 || raw_line )

    which removes boundary-ambiguity and length-extension style collisions
    between distinct (record, previous-hash) pairs.
  - Lines are parsed as strict JSON (duplicate keys and NaN/Infinity
    rejected) with line-numbered errors (audit finding L-11).
  - The main path streams the file line-by-line, O(1) memory (L-11).

Schema entropy (audit finding L-3):

  The root is a plain SHA-256 over the log lines. If the records are
  low-cardinality (few distinct agents / resources / decisions, no
  high-entropy field), publishing the root on-chain lets an observer
  confirm guessed record contents by recomputing the chain. The demo
  generator puts a UUID + ISO timestamp in every record so it is not
  practically brute-forceable, but a real firewall log MUST be assessed.

  Mitigation: set AUDIT_CHAIN_SALT to >= 16 random bytes (hex). It is
  mixed into every chain step, turning the root into a keyed value that
  cannot be recomputed without the salt. The SAME AUDIT_CHAIN_SALT must
  be set wherever the chain is verified.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Iterable, Iterator

if sys.version_info < (3, 9):
    raise SystemExit("audit tooling requires Python >= 3.9")

LOG_FILE = Path(__file__).parent / "audit_log.jsonl"
CHAIN_FILE = Path(__file__).parent / "audit_chain.jsonl"
ROOT_HASH_FILE = Path(__file__).parent / "root_hash.txt"

GENESIS = b"\x00" * 32
DELIM = b"\x1f"  # ASCII unit separator
LEN_BYTES = 8    # big-endian length-prefix width
SALT_ENV = "AUDIT_CHAIN_SALT"
_JSON_DUMP = dict(separators=(",", ":"), ensure_ascii=True)


class EmptyLogError(ValueError):
    """Raised when there are zero records to chain (M-1)."""


def _load_salt() -> bytes:
    raw = os.environ.get(SALT_ENV, "").strip()
    if not raw:
        return b""
    try:
        salt = bytes.fromhex(raw)
    except ValueError:
        raise SystemExit(f"{SALT_ENV} must be hex")
    if len(salt) < 16:
        raise SystemExit(f"{SALT_ENV} must be >= 16 bytes (32 hex chars)")
    return salt


SALT = _load_salt()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    seen: dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r} in audit record")
        seen[key] = value
    return seen


def _reject_constant(token: str):
    raise ValueError(f"non-finite JSON constant {token!r} in audit record")


def _parse_record(raw_line: bytes, lineno: int | None = None) -> dict:
    where = f"line {lineno}: " if lineno is not None else ""
    try:
        return json.loads(
            raw_line.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"{where}invalid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{where}{exc}") from exc


def iter_raw_lines(path: Path = LOG_FILE) -> Iterator[tuple[int, bytes]]:
    """Stream (lineno, raw_bytes) for each non-empty line, as stored on disk.

    Byte-identical to splitting the file on b"\\n": the trailing newline is
    removed, everything else (incl. a trailing "\\r") is kept.
    """
    seen = False
    try:
        f = open(path, "rb")
    except FileNotFoundError as exc:
        raise EmptyLogError(f"{path} does not exist") from exc
    with f:
        for lineno, raw in enumerate(f, start=1):
            if raw.endswith(b"\n"):
                raw = raw[:-1]
            if raw.strip():
                seen = True
                yield lineno, raw
    if not seen:
        raise EmptyLogError(f"{path} contains no audit records")


def load_lines(path: Path = LOG_FILE) -> list[bytes]:
    """Raw non-empty lines (M-1: empty / missing -> EmptyLogError)."""
    return [raw for _lineno, raw in iter_raw_lines(path)]


def load_records(path: Path = LOG_FILE) -> list[dict]:
    """Decoded records (strict JSON, line-numbered errors)."""
    return [_parse_record(raw, lineno) for lineno, raw in iter_raw_lines(path)]


def _chain_step(prev_hash: bytes, raw_line: bytes, salt: bytes = SALT) -> bytes:
    if len(prev_hash) != 32:
        raise ValueError("prev_hash must be 32 bytes")
    hasher = hashlib.sha256()
    if salt:
        hasher.update(b"midnight-side/audit-chain-salt/v1")
        hasher.update(len(salt).to_bytes(2, "big"))
        hasher.update(salt)
    hasher.update(prev_hash)
    hasher.update(DELIM)
    hasher.update(len(raw_line).to_bytes(LEN_BYTES, "big"))
    hasher.update(raw_line)
    return hasher.digest()


def canonical_bytes(record: dict) -> bytes:
    """Strict deterministic JSON: sorted keys, no whitespace, ASCII, no NaN.
    Used only by build_chain_from_records (callers without the raw lines)."""
    return json.dumps(record, sort_keys=True, allow_nan=False, **_JSON_DUMP).encode(
        "utf-8"
    )


def build_chain(
    lines: Iterable[bytes], salt: bytes = SALT
) -> tuple[list[dict], str]:
    """In-memory hash chain over raw line bytes. Returns (chain, root_hex)."""
    chain: list[dict] = []
    prev = GENESIS
    for i, raw in enumerate(lines, start=1):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        record = _parse_record(raw, i)
        cur = _chain_step(prev, raw, salt)
        chain.append({"record": record, "prev_hash": prev.hex(), "hash": cur.hex()})
        prev = cur
    if not chain:
        raise EmptyLogError("cannot build a hash chain over zero records")
    return chain, prev.hex()


def build_chain_from_records(
    records: Iterable[dict], salt: bytes = SALT
) -> tuple[list[dict], str]:
    """Chain over records not read from disk, via canonical_bytes."""
    lines = [canonical_bytes(r) for r in records]
    if not lines:
        raise EmptyLogError("cannot build a hash chain over zero records")
    return build_chain(lines, salt)


def build_chain_streaming(
    path: Path = LOG_FILE,
    salt: bytes = SALT,
    chain_file: Path | None = None,
) -> tuple[int, str]:
    """Stream the log line-by-line (O(1) memory, L-11). Optionally write the
    chain entries to `chain_file` as they are produced. Returns (count, root_hex)."""
    prev = GENESIS
    count = 0
    out = open(chain_file, "w", encoding="utf-8") if chain_file is not None else None
    try:
        for lineno, raw in iter_raw_lines(path):
            record = _parse_record(raw, lineno)
            cur = _chain_step(prev, raw, salt)
            if out is not None:
                out.write(
                    json.dumps(
                        {"record": record, "prev_hash": prev.hex(), "hash": cur.hex()},
                        **_JSON_DUMP,
                    )
                    + "\n"
                )
            prev = cur
            count += 1
    finally:
        if out is not None:
            out.close()
    if count == 0:
        raise EmptyLogError(f"{path} contains no audit records")
    return count, prev.hex()


if __name__ == "__main__":
    try:
        count, root_hash = build_chain_streaming(LOG_FILE, chain_file=CHAIN_FILE)
    except (EmptyLogError, ValueError) as exc:
        raise SystemExit(f"hash_chain: {exc}")

    ROOT_HASH_FILE.write_text(root_hash, encoding="utf-8")
    if SALT:
        print(f"(salted via {SALT_ENV})")
    print(f"Chained {count} records")
    print(f"Root hash (this is what gets committed on-chain): {root_hash}")
