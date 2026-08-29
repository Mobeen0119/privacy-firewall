"""Output inspection firewall.

Last checkpoint before an LLM response is handed back to a caller. The
policy engine and data minimizer decide what goes *in*; this module
checks what comes *out*, on the assumption that a model can echo,
paraphrase, or hallucinate sensitive data regardless of what it was
given (project README, sections on prompt injection and untrusted model
output).

Two independent checks:

  * Canary leak  - any registered canary token in the output means data
                   that was never supposed to be reachable has been
                   reached. Hard block. Detection is resistant to simple
                   evasion: verbatim, whitespace/newline-broken, and
                   base64-encoded (std + urlsafe) occurrences all count.
  * Unmasked PII - emails, phone numbers, credentials, credit cards,
                   SSNs, and person names that the caller was not
                   explicitly authorised to see (``allowed_fields``).

Any violation -> ``decision="BLOCK"``, ``output=None``. Otherwise
``decision="ALLOW"`` with the output passed through unchanged.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field as dataclass_field
from typing import Iterable

from .pii_detector import PIIDetector, PIIType

ALLOW = "ALLOW"
BLOCK = "BLOCK"

# Which allowed-field name fragments authorise which PII type. API_KEY is
# absent on purpose: a credential in model output is never acceptable.
_FIELD_KEYWORDS: dict[PIIType, frozenset[str]] = {
    PIIType.EMAIL: frozenset({"email", "e_mail", "mail"}),
    PIIType.PHONE_NUMBER: frozenset({"phone", "phone_number", "mobile", "tel", "telephone"}),
    PIIType.PERSON_NAME: frozenset({"name", "full_name", "first_name", "last_name"}),
    PIIType.CREDIT_CARD: frozenset({"credit_card", "card", "card_number", "cc", "pan"}),
    PIIType.SSN: frozenset({"ssn", "social_security", "social_security_number"}),
}


@dataclass(frozen=True)
class OutputViolation:
    """One reason an output was blocked."""

    kind: str          # "canary" | "pii"
    detail: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.detail


@dataclass(frozen=True)
class OutputDecision:
    decision: str                       # ALLOW | BLOCK
    reason: str
    output: str | None
    violations: list[OutputViolation] = dataclass_field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return self.decision == BLOCK

    @property
    def is_allowed(self) -> bool:
        return self.decision == ALLOW


class OutputFirewall:
    """Inspects raw LLM output for data leakage before it is returned."""

    def __init__(
        self,
        pii_detector: PIIDetector | None = None,
        canary_tokens: Iterable[str] | None = None,
    ) -> None:
        self.pii_detector = pii_detector or PIIDetector()
        self._canaries: list[str] = self._load_canaries(canary_tokens)

    # -- canary registry -------------------------------------------------

    @staticmethod
    def _load_canaries(source: Iterable[str] | None) -> list[str]:
        """Accept a plain iterable of tokens, or a registry object that
        exposes a ``tokens()`` method returning one."""
        if source is None:
            return []
        if hasattr(source, "tokens") and callable(source.tokens):
            source = source.tokens()
        return [t for t in source if isinstance(t, str) and t]

    def register_canary(self, token: str) -> None:
        if token and token not in self._canaries:
            self._canaries.append(token)

    @property
    def canary_tokens(self) -> list[str]:
        return list(self._canaries)

    # -- inspection ----------------------------------------------------

    def inspect_response(
        self,
        raw_output: str,
        allowed_fields: list[str] | None = None,
    ) -> OutputDecision:
        text = raw_output or ""
        allowed = self._normalise_allowed(allowed_fields)

        violations: list[OutputViolation] = []
        violations += self._scan_canaries(text)
        violations += self._scan_pii(text, allowed)

        if violations:
            details = "; ".join(v.detail for v in violations)
            return OutputDecision(
                decision=BLOCK,
                reason=f"Data leakage detected: {details}",
                output=None,
                violations=violations,
            )

        return OutputDecision(
            decision=ALLOW,
            reason="No leakage detected",
            output=raw_output,
            violations=[],
        )

    # -- scanners ----------------------------------------------------

    _B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")

    def _scan_canaries(self, text: str) -> list[OutputViolation]:
        """Detect canary tokens even when lightly obfuscated.

        Strategies, in order of specificity:
          1. verbatim substring,
          2. whitespace-stripped text (defeats space / newline splitting),
          3. base64-decoded runs (std and urlsafe alphabets).
        Each token is reported at most once, tagged with how it was found.
        """
        if not text:
            return []

        stripped = re.sub(r"\s+", "", text)
        decoded_blobs = self._decode_b64_runs(text)

        out: list[OutputViolation] = []
        for token in self._canaries:
            how: str | None = None
            if token in text:
                how = "verbatim"
            elif token in stripped:
                how = "whitespace-obfuscated"
            elif any(token in blob for blob in decoded_blobs):
                how = "base64-encoded"
            if how:
                out.append(OutputViolation(
                    "canary", f"canary token '{token}' present in output ({how})"
                ))
        return out

    @classmethod
    def _decode_b64_runs(cls, text: str) -> list[str]:
        blobs: list[str] = []
        for m in cls._B64_RUN.finditer(text):
            run = m.group().rstrip("=")
            # Try both the standard and urlsafe alphabets by mapping the
            # urlsafe chars onto the standard ones before decoding.
            for candidate in {run, run.replace("-", "+").replace("_", "/")}:
                padded = candidate + "=" * (-len(candidate) % 4)
                try:
                    raw = base64.b64decode(padded.encode("ascii"), validate=True)
                except (binascii.Error, ValueError):
                    continue
                if raw:
                    blobs.append(raw.decode("utf-8", "ignore"))
        return blobs

    def _scan_pii(self, text: str, allowed: set[str]) -> list[OutputViolation]:
        out: list[OutputViolation] = []
        for ent in self.pii_detector.detect(text):
            if self._is_authorised(ent.type, allowed):
                continue
            out.append(
                OutputViolation(
                    "pii",
                    f"unmasked {ent.type.value} '{ent.value}' in output",
                )
            )
        return out

    # -- allowed-field matching ----------------------------------------

    @staticmethod
    def _normalise_allowed(allowed_fields: list[str] | None) -> set[str]:
        norm: set[str] = set()
        for f in allowed_fields or []:
            f = f.strip().lower()
            if not f:
                continue
            norm.add(f)
            norm.add(f.rsplit(".", 1)[-1])  # 'employee.email' -> 'email'
        return norm

    @staticmethod
    def _is_authorised(ptype: PIIType, allowed: set[str]) -> bool:
        keywords = _FIELD_KEYWORDS.get(ptype)
        if not keywords:
            return False  # API_KEY / anything unmapped: never authorised
        return bool(keywords & allowed)
