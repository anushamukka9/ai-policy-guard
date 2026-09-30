"""Audit logging for policy decisions.

Every decision made by :class:`policy_guard.guard.InferenceGuard` can be
appended to an audit trail as one JSON object per line (JSONL). Payloads
are summarized, never stored verbatim: string values become
``"<str len=N>"`` and nested structures are collapsed, so prompts,
responses, and PII never land in the log.

Sinks: a file path (JSONL appended), the string ``"stdout"``, any callable
taking a dict, or ``None`` (discard).
"""

from __future__ import annotations

import datetime as _datetime
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Callable

MAX_SUMMARY_DEPTH = 2


def summarize_value(value: Any, depth: int = 0) -> Any:
    """Privacy-safe summary of a payload value for audit entries."""
    if isinstance(value, str):
        return f"<str len={len(value)}>"
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if value is None:
        return None
    if isinstance(value, dict):
        if depth >= MAX_SUMMARY_DEPTH:
            return f"<dict keys={len(value)}>"
        return {str(k): summarize_value(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        if depth >= MAX_SUMMARY_DEPTH:
            return f"<list len={len(value)}>"
        return [summarize_value(v, depth + 1) for v in value[:5]]
    return f"<{type(value).__name__}>"


def utc_now_iso() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat()


class AuditLogger:
    """Appends decision records to a JSONL audit trail."""

    def __init__(self, sink: str | Path | Callable[[dict], None] | None = None):
        self.sink = sink
        self._file = None
        if isinstance(sink, (str, Path)) and sink != "stdout":
            # Held open for the logger's lifetime; closed via close().
            self._file = open(sink, "a", encoding="utf-8")  # noqa: SIM115

    def log(self, event: str, payload: dict[str, Any]) -> None:
        entry = {"ts": utc_now_iso(), "event": event, **payload}
        if self._file is not None:
            self._file.write(json.dumps(entry, default=str) + "\n")
            self._file.flush()
        elif self.sink == "stdout":
            print(json.dumps(entry, default=str))
        elif callable(self.sink):
            self.sink(entry)
        # sink=None discards

    def log_decision(self, decision: Any, payload_summary: dict[str, Any] | None = None) -> None:
        """Log a Decision. Pass the (already redacted) payload summary to log."""
        record = decision.to_dict()
        if payload_summary is not None:
            record["payload"] = summarize_value(payload_summary)
        self.log("decision", record)

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None


def read_audit_log(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield audit entries from a JSONL file, skipping malformed lines."""
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
