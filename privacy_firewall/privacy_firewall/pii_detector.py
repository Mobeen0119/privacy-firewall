"""PII and secret detection.

Scans free text (a prompt, an LLM response, a log line) for personal
data and credentials *before* it leaves the trust boundary. This is the
"catch the thing the policy engine can't see" layer: the policy engine
reasons about structured fields it was told about, this module reasons
about whatever unstructured string is actually in flight.

Detection is pure regex + light heuristics + a Luhn check. No model
weights, no network. That keeps it fast, deterministic, and safe to run
inline on every request (project README, "Fail closed" and section 9).

Detected categories (see :class:`PIIType`):

  * EMAIL
  * PHONE_NUMBER
  * API_KEY          - labelled secrets, UUIDs, JWTs, high-entropy tokens
  * PERSON_NAME      - capitalised-name heuristic, optional title
  * CREDIT_CARD      - 13-19 digits, Luhn-valid
  * SSN              - US Social Security number

Masking (:meth:`PIIDetector.mask`) supports three strategies:

  * ``"redact"``  -> ``[REDACTED_EMAIL]``
  * ``"token"``   -> ``EMAIL_001`` (stable within one call: equal values
                     map to the same token)
  * ``"hash"``    -> ``EMAIL_9af1c2b7`` (first 8 hex of SHA-256)
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class PIIType(str, Enum):
    EMAIL = "EMAIL"
    PHONE_NUMBER = "PHONE_NUMBER"
    API_KEY = "API_KEY"
    PERSON_NAME = "PERSON_NAME"
    CREDIT_CARD = "CREDIT_CARD"
    SSN = "SSN"


@dataclass(frozen=True)
class PIIEntity:
    """One detected span of sensitive data.

    ``start``/``end`` are half-open character offsets into the text that
    was scanned, so ``text[start:end] == value``.
    """

    type: PIIType
    value: str
    start: int
    end: int
    score: float = 1.0

    def __len__(self) -> int:
        return self.end - self.start


# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# US / international-ish phone numbers. A separator (space, dot, dash) or
# a leading +country code is mandatory so that a bare 10-digit blob is
# not swept up as a phone number by accident.
_PHONE_RE = re.compile(
    r"""(?<![\w.])(
        \+\d{1,3}[\s.\-]\d{1,4}[\s.\-]\d{2,4}(?:[\s.\-]\d{2,4})?   # +cc grouped
      |
        (?:\+\d{1,3}[\s.\-]?)?          # optional +country
        (?:\(\d{3}\)|\d{3})             # area code, optionally parenthesised
        [\s.\-]                         # a real separator (mandatory)
        \d{3}
        [\s.\-]?
        \d{4}
    )(?![\w])""",
    re.VERBOSE,
)

_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

# Generic credential / secret labels worth flagging even when entropy is
# modest. Vendor-specific key prefixes (Stripe, AWS, GitHub, Google, Slack)
# are intentionally NOT hard-coded here: real vendor keys are long
# high-entropy strings already caught by _find_high_entropy_tokens, and
# embedding live-looking prefixes in source trips secret scanners such as
# GitHub push protection.
_KNOWN_SECRET_RE = re.compile(
    r"""(?<![A-Za-z0-9_])(
          (?:MOCK|TEST|DEMO|FAKE|SAMPLE|DUMMY)_(?:API_KEY|SECRET_KEY|SECRET|ACCESS_KEY|TOKEN|KEY)_[A-Za-z0-9]{6,}
        | (?:API_KEY|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|AUTH_TOKEN)_[A-Za-z0-9]{10,}
        | eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}   # JWT (structural)
    )(?![A-Za-z0-9])""",
    re.VERBOSE,
)

# Generic high-entropy blob: long run of token characters. Kept separate
# because it needs an entropy check before it counts.
_TOKEN_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9/+_\-])[A-Za-z0-9/+_\-]{24,}(?![A-Za-z0-9/+_\-])")

# 13-19 digit card-like runs, optionally spaced/dashed in groups.
_CARD_CANDIDATE_RE = re.compile(r"(?<![\d\-])(?:\d[ \-]?){12,18}\d(?![\d\-])")

# Title + name, or two/three capitalised words in a row.
_NAME_RE = re.compile(
    r"\b(?:(?P<title>Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+)?"
    r"(?P<name>[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"
)

# Capitalised words that are almost never a person's name. Keeps the
# name heuristic from firing on "New York", "United States", etc.
_NAME_STOPWORDS = {
    "New", "York", "United", "States", "Los", "Angeles", "San", "Francisco",
    "North", "South", "East", "West", "Monday", "Tuesday", "Wednesday",
    "Thursday", "Friday", "Saturday", "Sunday", "January", "February",
    "March", "April", "May", "June", "July", "August", "September",
    "October", "November", "December", "The", "This", "That", "These",
    "Please", "Thanks", "Thank", "Hello", "Hi", "Dear", "Best", "Regards",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits]
    checksum = 0
    parity = len(nums) % 2
    for i, d in enumerate(nums):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class PIIDetector:
    """Detects and masks PII / secrets in arbitrary text."""

    # Higher wins when two spans overlap.
    _PRIORITY = {
        PIIType.CREDIT_CARD: 6,
        PIIType.SSN: 5,
        PIIType.API_KEY: 4,
        PIIType.EMAIL: 3,
        PIIType.PHONE_NUMBER: 2,
        PIIType.PERSON_NAME: 1,
    }

    def __init__(self, entropy_threshold: float = 3.5, min_token_len: int = 24) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_token_len = min_token_len

    # -- public API --------------------------------------------------------

    def detect(self, text: str) -> list[PIIEntity]:
        """Return every PII span found in ``text``, ordered by position.

        Overlapping matches are resolved in favour of the higher-priority
        / longer span, so a credit card is never also reported as a phone
        number.
        """
        if not text:
            return []

        found: list[PIIEntity] = []
        found += self._find_regex(text, _EMAIL_RE, PIIType.EMAIL)
        found += self._find_regex(text, _SSN_RE, PIIType.SSN)
        found += self._find_regex(text, _PHONE_RE, PIIType.PHONE_NUMBER)
        found += self._find_regex(text, _KNOWN_SECRET_RE, PIIType.API_KEY)
        found += self._find_regex(text, _UUID_RE, PIIType.API_KEY, score=0.8)
        found += self._find_high_entropy_tokens(text)
        found += self._find_credit_cards(text)
        found += self._find_names(text)

        return self._resolve_overlaps(found)

    def has_pii(self, text: str) -> bool:
        return bool(self.detect(text))

    def mask(self, text: str, strategy: str = "token") -> str:
        """Return ``text`` with every detected span replaced.

        ``strategy`` is one of ``"redact"``, ``"token"``, ``"hash"``.
        Replacement runs right-to-left so earlier offsets stay valid.
        """
        if strategy not in ("redact", "token", "hash"):
            raise ValueError(
                f"Unknown strategy {strategy!r}; expected 'redact', 'token' or 'hash'"
            )

        entities = self.detect(text)
        if not entities:
            return text

        # Assign token numbers left-to-right so equal values share the
        # lowest number, then do the actual splicing right-to-left.
        token_counters: dict[PIIType, int] = {}
        token_seen: dict[tuple[PIIType, str], str] = {}
        if strategy == "token":
            for ent in entities:
                key = (ent.type, ent.value)
                if key not in token_seen:
                    token_counters[ent.type] = token_counters.get(ent.type, 0) + 1
                    token_seen[key] = f"{ent.type.value}_{token_counters[ent.type]:03d}"

        out = text
        for ent in sorted(entities, key=lambda e: e.start, reverse=True):
            out = out[: ent.start] + self._placeholder(
                ent, strategy, token_counters, token_seen
            ) + out[ent.end :]
        return out

    # -- placeholder rendering ------------------------------------------------

    @staticmethod
    def _placeholder(
        ent: PIIEntity,
        strategy: str,
        counters: dict[PIIType, int],
        seen: dict[tuple[PIIType, str], str],
    ) -> str:
        if strategy == "redact":
            return f"[REDACTED_{ent.type.value}]"
        if strategy == "hash":
            digest = hashlib.sha256(ent.value.encode("utf-8")).hexdigest()[:8]
            return f"{ent.type.value}_{digest}"
        # token: stable per (type, value) within this call
        key = (ent.type, ent.value)
        if key not in seen:
            counters[ent.type] = counters.get(ent.type, 0) + 1
            seen[key] = f"{ent.type.value}_{counters[ent.type]:03d}"
        return seen[key]

    # -- finders -----------------------------------------------------------

    @staticmethod
    def _find_regex(
        text: str, pattern: re.Pattern[str], ptype: PIIType, score: float = 1.0
    ) -> list[PIIEntity]:
        out: list[PIIEntity] = []
        for m in pattern.finditer(text):
            # If the pattern has a capturing group 1, prefer it (strips
            # leading separators from e.g. the phone pattern).
            if m.re.groups >= 1 and m.group(1) is not None:
                start, end = m.start(1), m.end(1)
            else:
                start, end = m.start(), m.end()
            out.append(PIIEntity(ptype, text[start:end], start, end, score))
        return out

    def _find_high_entropy_tokens(self, text: str) -> list[PIIEntity]:
        out: list[PIIEntity] = []
        for m in _TOKEN_CANDIDATE_RE.finditer(text):
            blob = m.group()
            if len(blob) < self.min_token_len:
                continue
            if not any(c.isdigit() for c in blob):
                continue  # all-letters run is likely prose, not a key
            if _shannon_entropy(blob) < self.entropy_threshold:
                continue
            out.append(PIIEntity(PIIType.API_KEY, blob, m.start(), m.end(), 0.7))
        return out

    @staticmethod
    def _find_credit_cards(text: str) -> list[PIIEntity]:
        out: list[PIIEntity] = []
        for m in _CARD_CANDIDATE_RE.finditer(text):
            raw = m.group()
            digits = re.sub(r"[ \-]", "", raw)
            if not (13 <= len(digits) <= 19):
                continue
            if not _luhn_ok(digits):
                continue
            out.append(PIIEntity(PIIType.CREDIT_CARD, raw, m.start(), m.end(), 0.95))
        return out

    @staticmethod
    def _find_names(text: str) -> list[PIIEntity]:
        out: list[PIIEntity] = []
        for m in _NAME_RE.finditer(text):
            name = m.group("name")
            words = name.split()
            if any(w in _NAME_STOPWORDS for w in words):
                continue
            # Span covers the title too, if present.
            start = m.start("title") if m.group("title") else m.start("name")
            out.append(PIIEntity(PIIType.PERSON_NAME, text[start:m.end("name")], start, m.end("name"), 0.6))
        return out

    # -- overlap resolution ----------------------------------------------------

    def _resolve_overlaps(self, entities: Iterable[PIIEntity]) -> list[PIIEntity]:
        ordered = sorted(
            entities,
            key=lambda e: (e.start, -(len(e)), -self._PRIORITY[e.type]),
        )
        kept: list[PIIEntity] = []
        for ent in ordered:
            clash = None
            for k in kept:
                if ent.start < k.end and k.start < ent.end:
                    clash = k
                    break
            if clash is None:
                kept.append(ent)
                continue
            if self._beats(ent, clash):
                kept.remove(clash)
                kept.append(ent)
        kept.sort(key=lambda e: e.start)
        return kept

    def _beats(self, a: PIIEntity, b: PIIEntity) -> bool:
        pa, pb = self._PRIORITY[a.type], self._PRIORITY[b.type]
        if pa != pb:
            return pa > pb
        if len(a) != len(b):
            return len(a) > len(b)
        return a.score > b.score


# Module-level convenience -------------------------------------------------

_DEFAULT = PIIDetector()


def detect(text: str) -> list[PIIEntity]:
    return _DEFAULT.detect(text)


def mask(text: str, strategy: str = "token") -> str:
    return _DEFAULT.mask(text, strategy)


def has_pii(text: str) -> bool:
    return _DEFAULT.has_pii(text)
