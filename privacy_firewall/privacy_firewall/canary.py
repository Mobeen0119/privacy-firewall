"""Canary token management for leak detection.

A canary is a unique, meaningless string planted in the data store. It has
no legitimate reason to appear in anything an agent or an LLM produces, so
if one shows up in an agent-visible payload or a model response, data that
should have been blocked has leaked.

Used two ways:

  * seeded into :class:`~privacy_firewall.agent.MockEmployeeDB` rows via
    :meth:`CanaryManager.inject_into_db`,
  * handed to :class:`~privacy_firewall.output_firewall.OutputFirewall` as
    the canary registry (``CanaryManager`` exposes a ``tokens()`` method,
    which is the shape the firewall accepts).

:meth:`verify_leak` returns ``True`` when a leak is present.
"""

from __future__ import annotations

import random
from typing import Any

DEFAULT_PREFIX = "CANARY-SECRET-"


class CanaryManager:
    """Generates and tracks canary tokens, and checks text for leaks."""

    def __init__(
        self,
        prefix: str = DEFAULT_PREFIX,
        token_len: int = 8,
        seed: int | None = None,
    ) -> None:
        if token_len < 4:
            raise ValueError("token_len must be >= 4")
        self.prefix = prefix
        self.token_len = token_len
        self._rng = random.Random(seed)
        self._tokens: list[str] = []                 # every token ever issued
        self._by_row: dict[Any, str] = {}            # row id -> injected token

    # -- generation ------------------------------------------------------

    def generate_canary(self) -> str:
        """Issue a fresh, unique tracked canary token."""
        while True:
            body = "".join(self._rng.choice("0123456789abcdef") for _ in range(self.token_len))
            token = f"{self.prefix}{body}"
            if token not in self._tokens:
                self._tokens.append(token)
                return token

    # -- injection -----------------------------------------------------

    def inject_into_db(self, db: Any) -> dict[Any, str]:
        """Plant one fresh canary in every row of ``db``.

        Works on the mock DB's per-instance row list. Returns a mapping of
        row id -> the token planted in that row.
        """
        rows = self._row_list(db)
        planted: dict[Any, str] = {}
        for row in rows:
            token = self.generate_canary()
            row_id = row.get("id", id(row))
            note = row.get("notes", "")
            row["notes"] = f"{note} [audit-ref {token}]".strip()
            planted[row_id] = token
            self._by_row[row_id] = token
        return planted

    @staticmethod
    def _row_list(db: Any) -> list[dict[str, Any]]:
        for attr in ("_rows", "_ROWS", "rows"):
            rows = getattr(db, attr, None)
            if isinstance(rows, list):
                return rows
        raise TypeError(
            "inject_into_db needs an object exposing a mutable row list "
            "(_rows / _ROWS / rows)"
        )

    # -- verification -------------------------------------------------

    def verify_leak(self, text: str) -> bool:
        """True if any tracked canary appears verbatim in ``text``."""
        if not text:
            return False
        return any(token in text for token in self._tokens)

    def leaked_tokens(self, text: str) -> list[str]:
        """Every tracked canary found in ``text`` (for diagnostics)."""
        if not text:
            return []
        return [token for token in self._tokens if token in text]

    def assert_no_leak(self, text: str) -> None:
        leaked = self.leaked_tokens(text)
        if leaked:
            raise AssertionError(f"canary leak: {leaked}")

    # -- registry interface for OutputFirewall ----------------------

    def tokens(self) -> list[str]:
        return list(self._tokens)

    @property
    def all_tokens(self) -> list[str]:
        return list(self._tokens)

    def reset(self) -> None:
        self._tokens.clear()
        self._by_row.clear()
