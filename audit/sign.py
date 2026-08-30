"""Ed25519 signing for the audit hash-chain root hash.

Key hygiene (H-1): the private key file is created with mode 0600 via
os.open (no world-readable window); with FIREWALL_KEY_PASSPHRASE set it is
serialized with BestAvailableEncryption, otherwise written unencrypted and
the tool says so.

Fail-closed verification (H-2): verify_signature / verify_commit_signature
catch every exception and return a strict False.

Context-bound signatures (M-2): the signed message is not the bare root
hash but

    SHA256( "midnight-side/audit-commit/v1"
            || len16(network_id)  || network_id
            || len16(contract_addr) || contract_addr
            || epoch_u64_be
            || root_hash_32 )

The two variable-length fields are length-prefixed so the concatenation is
unambiguous.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

if sys.version_info < (3, 9):
    raise SystemExit("audit tooling requires Python >= 3.9")

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

PRIVATE_KEY_PATH = Path(__file__).parent / "firewall_signing_key.pem"
PUBLIC_KEY_PATH = Path(__file__).parent / "firewall_verify_key.pem"

PASSPHRASE_ENV = "FIREWALL_KEY_PASSPHRASE"
COMMIT_DOMAIN = b"midnight-side/audit-commit/v1"
ZERO_ROOT_HEX = "0" * 64


def _passphrase() -> bytes | None:
    value = os.environ.get(PASSPHRASE_ENV)
    if not value:
        return None
    return value.encode("utf-8")


def _write_private_bytes(path: Path, data: bytes) -> None:
    """Write private-key bytes with 0600 from creation (no umask race)."""
    fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def generate_keypair(
    private_path: Path = PRIVATE_KEY_PATH,
    public_path: Path = PUBLIC_KEY_PATH,
    *,
    overwrite: bool = False,
) -> None:
    # M-3: refuse to clobber either existing key file without --force.
    if not overwrite:
        for existing in (private_path, public_path):
            if existing.exists():
                raise SystemExit(
                    f"{existing} already exists. Refusing to overwrite: rotating the "
                    f"key invalidates every previously produced signature. "
                    f"Re-run as 'python sign.py generate --force' to proceed."
                )

    passphrase = _passphrase()
    if passphrase is None:
        encryption = serialization.NoEncryption()
        how = f"UNENCRYPTED (set {PASSPHRASE_ENV} to encrypt the private key)"
    else:
        encryption = serialization.BestAvailableEncryption(passphrase)
        how = f"encrypted via {PASSPHRASE_ENV}"

    private_key = Ed25519PrivateKey.generate()
    _write_private_bytes(
        private_path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        ),
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    # Human output on stderr so stdout stays clean for wrapper scripts (L-13).
    print(f"Private key: {private_path} (mode 0600, {how})", file=sys.stderr)
    print(f"Public key:  {public_path}", file=sys.stderr)


def _require_root_hash_hex(root_hash_hex: str) -> bytes:
    if not isinstance(root_hash_hex, str) or len(root_hash_hex) != 64:
        raise ValueError("root hash must be 64 hex characters (32 bytes)")
    if root_hash_hex.lower() == ZERO_ROOT_HEX:
        raise ValueError("root hash is all-zero (empty chain); refusing to sign/verify")
    return bytes.fromhex(root_hash_hex)  # raises ValueError on non-hex


def build_commit_message(
    root_hash_hex: str,
    network_id: str,
    contract_address: str,
    epoch: int,
) -> bytes:
    """32-byte digest that is actually signed/verified (M-2)."""
    root = _require_root_hash_hex(root_hash_hex)
    nid = str(network_id).encode("utf-8")
    addr = str(contract_address).encode("utf-8")
    ep = int(epoch)
    if not (0 <= ep < 2**64):
        raise ValueError("epoch must fit in an unsigned 64-bit integer")
    if len(nid) > 0xFFFF or len(addr) > 0xFFFF:
        raise ValueError("network_id / contract_address too long")

    h = hashlib.sha256()
    h.update(COMMIT_DOMAIN)
    h.update(len(nid).to_bytes(2, "big"))
    h.update(nid)
    h.update(len(addr).to_bytes(2, "big"))
    h.update(addr)
    h.update(ep.to_bytes(8, "big"))
    h.update(root)
    return h.digest()


def _load_private_key(private_key_path: Path):
    try:
        key = serialization.load_pem_private_key(
            private_key_path.read_bytes(), password=_passphrase()
        )
    except TypeError as exc:
        raise SystemExit(
            f"cannot load {private_key_path}: {exc}. "
            f"Set {PASSPHRASE_ENV} to the private key's passphrase."
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("loaded key is not an Ed25519 private key")
    return key


def sign_commit(
    root_hash_hex: str,
    network_id: str,
    contract_address: str,
    epoch: int,
    private_key_path: Path = PRIVATE_KEY_PATH,
) -> str:
    message = build_commit_message(root_hash_hex, network_id, contract_address, epoch)
    return _load_private_key(private_key_path).sign(message).hex()


def verify_signature(
    message: bytes,
    signature_hex: str,
    verify_key_path: Path = PUBLIC_KEY_PATH,
) -> bool:
    """Low-level fail-closed Ed25519 verification over an exact message."""
    try:
        public_key = serialization.load_pem_public_key(verify_key_path.read_bytes())
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        public_key.verify(bytes.fromhex(signature_hex), message)
        return True
    except Exception:
        return False


def verify_commit_signature(
    root_hash_hex: str,
    signature_hex: str,
    network_id: str,
    contract_address: str,
    epoch: int,
    verify_key_path: Path = PUBLIC_KEY_PATH,
) -> bool:
    """Fail closed: rebuilds the context-bound message and verifies it."""
    try:
        message = build_commit_message(
            root_hash_hex, network_id, contract_address, epoch
        )
    except Exception:
        return False
    return verify_signature(message, signature_hex, verify_key_path)


USAGE = (
    "Usage:\n"
    "  python sign.py generate [--force]\n"
    "  python sign.py sign   <root_hash_hex> <network_id> <contract_address> <epoch> [--out FILE]\n"
    "  python sign.py verify <root_hash_hex> <signature_hex> <network_id> <contract_address> <epoch>"
)


def _die(msg: str, code: int = 2):
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def _parse_epoch(value: str) -> int:
    try:
        ep = int(value)
    except ValueError:
        _die(f"epoch must be an integer, got {value!r}")
    if ep < 0:
        _die("epoch must be non-negative")
    return ep


if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv:
        _die(USAGE)

    cmd, rest = argv[0], argv[1:]

    if cmd == "generate":
        if not set(rest) <= {"--force"}:
            _die(USAGE)
        generate_keypair(overwrite="--force" in rest)

    elif cmd == "sign":
        out_file = None
        if "--out" in rest:
            i = rest.index("--out")
            if i + 1 >= len(rest):
                _die("--out requires a file path")
            out_file, rest = rest[i + 1], rest[:i] + rest[i + 2 :]
        if len(rest) != 4:
            _die(USAGE)
        try:
            sig = sign_commit(rest[0], rest[1], rest[2], _parse_epoch(rest[3]))
        except ValueError as exc:
            _die(f"sign: {exc}", code=1)
        if out_file is not None:
            Path(out_file).write_text(sig + "\n", encoding="utf-8")
            print(f"signature written to {out_file}", file=sys.stderr)
        else:
            # L-13: raw signature hex ONLY, nothing else, on stdout.
            sys.stdout.write(sig + "\n")
            sys.stdout.flush()

    elif cmd == "verify":
        if len(rest) != 5:
            _die(USAGE)
        ok = verify_commit_signature(
            rest[0], rest[1], rest[2], rest[3], _parse_epoch(rest[4])
        )
        print("VALID" if ok else "INVALID")
        raise SystemExit(0 if ok else 1)

    else:
        _die(f"Unknown command: {cmd}\n{USAGE}")
