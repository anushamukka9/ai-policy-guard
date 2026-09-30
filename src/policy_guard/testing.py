"""Policy testing framework.

Policies are code: they deserve tests. A test file declares cases against a
policy set in YAML::

    apiVersion: policyguard.ai/v1
    kind: PolicyTest
    metadata:
      name: inference-guard-tests
    cases:
      - name: clean request is allowed
        request:
          prompt: "Summarize this document."
          user: {id: "u1", tier: "free"}
        expect:
          verdict: allow

      - name: secret in response is denied
        request:
          prompt: "Show me the API key."
          user: {id: "u1", tier: "free"}
        response:
          text: "The key is sk-abcdefghij1234567890"
        expect:
          verdict: deny
          fired: [block-secret-leak]

      - name: free tier is rate limited
        request:
          prompt: "Hi."
          user: {id: "u2", tier: "free"}
        repeat: 6
        expect:
          verdict: deny
          fired: [free-tier-rate-limit]

``expect.verdict`` is one of allow, deny, require_approval. ``expect.fired``
lists rule ids that must have fired (subset match). ``expect.redactions``
lists field paths that must have been redacted. ``repeat`` runs the same
case N times against a fresh guard (useful for rate-limit rules); the
verdict is taken from the last run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import AuditLogger
from .guard import Decision, InferenceGuard
from .policy import Policy


@dataclass
class PolicyTestCase:
    name: str
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] | None = None
    expect_verdict: str = "allow"
    expect_fired: list[str] = field(default_factory=list)
    expect_redactions: list[str] = field(default_factory=list)
    repeat: int = 1

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyTestCase:
        expect = data.get("expect", {}) or {}
        return cls(
            name=data.get("name", "unnamed case"),
            request=data.get("request", {}) or {},
            response=data.get("response"),
            expect_verdict=expect.get("verdict", "allow"),
            expect_fired=list(expect.get("fired", []) or []),
            expect_redactions=list(expect.get("redactions", []) or []),
            repeat=max(1, int(data.get("repeat", 1))),
        )


@dataclass
class CaseResult:
    name: str
    passed: bool
    expected: dict[str, Any]
    actual: dict[str, Any]
    diffs: list[str] = field(default_factory=list)


def load_test_file(path: str | Path) -> list[PolicyTestCase]:
    """Load test cases from a PolicyTest YAML file."""
    import yaml

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or data.get("kind") != "PolicyTest":
        raise ValueError(f"{path}: expected a PolicyTest document (kind: PolicyTest)")
    cases = data.get("cases") or []
    return [PolicyTestCase.from_dict(c) for c in cases]


def run_case(policies: list[Policy], case: PolicyTestCase) -> CaseResult:
    """Run one case against a fresh guard (isolated rate-limiter state)."""
    guard = InferenceGuard(policies, audit=AuditLogger(None))
    decision: Decision | None = None
    for _ in range(case.repeat):
        if case.response is None:
            decision = guard.evaluate_request(case.request)
        else:
            decision = guard.evaluate_response(case.request, case.response)
    assert decision is not None

    diffs: list[str] = []
    if decision.verdict != case.expect_verdict:
        diffs.append(f"verdict: expected {case.expect_verdict!r}, got {decision.verdict!r}")
    for rid in case.expect_fired:
        if rid not in decision.fired_rules:
            diffs.append(f"rule {rid!r} expected to fire; fired rules were {decision.fired_rules}")
    for field_path in case.expect_redactions:
        if field_path not in decision.redactions:
            diffs.append(
                f"field {field_path!r} expected to be redacted; "
                f"redacted fields were {decision.redactions}"
            )

    return CaseResult(
        name=case.name,
        passed=not diffs,
        expected={
            "verdict": case.expect_verdict,
            "fired": case.expect_fired,
            "redactions": case.expect_redactions,
        },
        actual={
            "verdict": decision.verdict,
            "fired": decision.fired_rules,
            "redactions": decision.redactions,
        },
        diffs=diffs,
    )


def run_suite(
    policies: list[Policy], cases: list[PolicyTestCase]
) -> tuple[list[CaseResult], dict[str, int]]:
    """Run every case; return (results, summary counts)."""
    results = [run_case(policies, case) for case in cases]
    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "failed": sum(1 for r in results if not r.passed),
    }
    return results, summary
