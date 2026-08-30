"""Verifies an audit log end to end (M-1, M-2, M-4):

  1. the hash chain rebuilds to `expected_root` (reject empty / 0...0);
  2. the context-bound signature over
     (domain, network_id, contract_address, epoch, expected_root)
     is valid against the firewall verify key;
  3. if an on-chain root is supplied (from the Midnight indexer via
     scripts/onchain.ts), it equals `expected_root`.

All three must hold. Fails closed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if sys.version_info < (3, 9):
    raise SystemExit("audit tooling requires Python >= 3.9")

import sign
from hash_chain import EmptyLogError, build_chain_streaming
from sign import ZERO_ROOT_HEX, verify_commit_signature

_HEX64 = set("0123456789abcdef")


def _is_hex64(value: str) -> bool:
    return len(value) == 64 and set(value.lower()) <= _HEX64


def verify_log(
    log_path: str,
    expected_root_hash: str,
    signature_hex: str,
    network_id: str,
    contract_address: str,
    epoch: int,
    onchain_root: str | None = None,
    require_onchain: bool = False,
    verify_key_path: Path | None = None,
) -> bool:
    # Late-bound so a reassigned sign.PUBLIC_KEY_PATH (tests, custom setups)
    # is honoured; callers may still pass an explicit path.
    key_path = verify_key_path if verify_key_path is not None else sign.PUBLIC_KEY_PATH
    expected = expected_root_hash.lower().strip()

    # M-1: never "verify" an empty / all-zero root.
    if not _is_hex64(expected):
        print(f"Expected root hash is not 64 hex chars: {expected_root_hash!r}")
        return False
    if expected == ZERO_ROOT_HEX:
        print("Expected root hash is all-zero (empty chain) - rejected.")
        return False

    try:
        _, computed = build_chain_streaming(Path(log_path))
    except EmptyLogError as exc:
        print(f"Empty / missing audit log: {exc}")
        return False
    except ValueError as exc:  # line-numbered parse error, bad structure
        print(f"Chain build failed: {exc}")
        return False

    chain_ok = computed == expected  # M-4: computed must match expected
    # M-2 / M-4: verify the signature over the EXPECTED (notarized) root,
    # bound to the deployment context.
    sig_ok = verify_commit_signature(
        expected, signature_hex, network_id, contract_address, epoch, key_path
    )

    if onchain_root is not None:
        onchain_ok: bool | None = onchain_root.lower().strip() == expected
    elif require_onchain:
        print("On-chain root required (--require-onchain) but none supplied.")
        onchain_ok = False
    else:
        onchain_ok = None  # skipped

    print(f"Computed root hash: {computed}")
    print(f"Expected root hash: {expected}")
    print(f"Chain integrity:    {'PASS' if chain_ok else 'FAIL'}")
    print(f"Signature check:    {'PASS' if sig_ok else 'FAIL'}")
    print(
        "On-chain check:    "
        + ("PASS" if onchain_ok else "SKIPPED" if onchain_ok is None else "FAIL")
    )

    return chain_ok and sig_ok and onchain_ok is not False


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="verify.py",
        description="Verify an audit log end to end (chain + signature + on-chain).",
        epilog=(
            "example: python verify.py audit_log.jsonl <root> <sig> "
            "--network preview --contract <addr> --epoch 0 [--onchain-root <hex>]"
        ),
    )
    p.add_argument("log_file", help="path to the audit log (JSONL)")
    p.add_argument("expected_root_hash", help="64-hex root that was notarized")
    p.add_argument("signature_hex", help="128-hex Ed25519 signature")
    p.add_argument("--network", required=True, help="network id used when signing")
    p.add_argument("--contract", required=True, help="contract address used when signing")
    p.add_argument("--epoch", required=True, type=int, help="epoch (commitCount) used when signing")
    p.add_argument("--onchain-root", dest="onchain_root", default=None,
                   help="root hash read back from the Midnight indexer")
    p.add_argument("--require-onchain", dest="require_onchain", action="store_true",
                   help="fail if --onchain-root is not supplied")
    return p


if __name__ == "__main__":
    ns = _build_parser().parse_args()
    ok = verify_log(
        ns.log_file,
        ns.expected_root_hash,
        ns.signature_hex,
        ns.network,
        ns.contract,
        ns.epoch,
        onchain_root=ns.onchain_root,
        require_onchain=ns.require_onchain,
    )
    print("\nOVERALL: PASS" if ok else "\nOVERALL: FAIL - tamper detected or invalid signature")
    sys.exit(0 if ok else 1)
