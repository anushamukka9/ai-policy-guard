"""Policy evaluation engine.

Evaluates an AI system's metadata document against a set of declarative
policies. The metadata document is the infrastructure-layer view of the
system: model card presence, evaluation scores, dataset lineage, deployment
target, data-handling flags, etc.

The engine resolves dotted paths (``model.evaluations.bias_score``) against
nested dicts and evaluates the assertion operator declared in each rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .policy import Assertion, Policy


@dataclass
class RuleOutcome:
    rule_id: str
    passed: bool
    severity: str
    description: str
    remediation: str = ""
    actual: Any = None
    expected: Any = None


@dataclass
class EvaluationResult:
    policy_name: str
    outcomes: list[RuleOutcome] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(not o.passed and o.severity == "block" for o in self.outcomes)

    @property
    def passed(self) -> bool:
        return not self.blocked

    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.outcomes),
            "passed": sum(1 for o in self.outcomes if o.passed),
            "failed": sum(1 for o in self.outcomes if not o.passed),
            "blocking_failures": sum(
                1 for o in self.outcomes if not o.passed and o.severity == "block"
            ),
        }


def resolve_path(document: dict[str, Any], path: str) -> Any:
    """Resolve a dotted path against nested dicts. Returns None when missing."""
    current: Any = document
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def set_path(document: dict[str, Any], path: str, value: Any) -> bool:
    """Set a dotted path inside nested dicts, creating dicts as needed.

    Returns True when the path was set, False when an intermediate segment
    exists but is not a dict.
    """
    parts = path.split(".")
    current = document
    for part in parts[:-1]:
        nxt = current.get(part)
        if nxt is None:
            nxt = {}
            current[part] = nxt
        if not isinstance(nxt, dict):
            return False
        current = nxt
    current[parts[-1]] = value
    return True


def _as_number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def evaluate_assertion(actual: Any, assertion: Assertion) -> tuple[bool, Any]:
    """Evaluate one assertion. Returns (passed, expected_description)."""
    if assertion.always:
        return (True, "always")
    if assertion.exists is not None:
        exists = actual is not None
        return (exists == assertion.exists, f"exists={assertion.exists}")
    if assertion.equals is not None:
        return (actual == assertion.equals, assertion.equals)
    if assertion.not_equals is not None:
        return (actual != assertion.not_equals, f"!={assertion.not_equals}")
    if assertion.in_list is not None:
        return (actual in assertion.in_list, assertion.in_list)
    if assertion.gte is not None:
        num = _as_number(actual)
        return (num is not None and num >= float(assertion.gte), f">={assertion.gte}")
    if assertion.lte is not None:
        num = _as_number(actual)
        return (num is not None and num <= float(assertion.lte), f"<={assertion.lte}")
    if assertion.contains is not None:
        if isinstance(actual, str):
            return (str(assertion.contains) in actual, f"contains {assertion.contains!r}")
        try:
            return (assertion.contains in actual, f"contains {assertion.contains!r}")
        except TypeError:
            return (False, f"contains {assertion.contains!r}")
    if assertion.not_contains is not None:
        if isinstance(actual, str):
            return (
                str(assertion.not_contains) not in actual,
                f"not contains {assertion.not_contains!r}",
            )
        try:
            return (
                assertion.not_contains not in actual,
                f"not contains {assertion.not_contains!r}",
            )
        except TypeError:
            return (False, f"not contains {assertion.not_contains!r}")
    if assertion.matches is not None:
        try:
            matched = isinstance(actual, str) and re.search(assertion.matches, actual) is not None
        except re.error:
            return (False, f"matches /{assertion.matches}/ (invalid pattern)")
        return (matched, f"matches /{assertion.matches}/")
    if assertion.startswith is not None:
        return (
            isinstance(actual, str) and actual.startswith(assertion.startswith),
            f"starts with {assertion.startswith!r}",
        )
    if assertion.endswith is not None:
        return (
            isinstance(actual, str) and actual.endswith(assertion.endswith),
            f"ends with {assertion.endswith!r}",
        )
    if assertion.length_gte is not None:
        try:
            return (len(actual) >= assertion.length_gte, f"length >= {assertion.length_gte}")
        except TypeError:
            return (False, f"length >= {assertion.length_gte}")
    if assertion.length_lte is not None:
        try:
            return (len(actual) <= assertion.length_lte, f"length <= {assertion.length_lte}")
        except TypeError:
            return (False, f"length <= {assertion.length_lte}")
    return (True, None)


def _short(value: Any, limit: int = 80) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def describe_assertion(assertion: Assertion, actual: Any, passed: bool) -> str:
    """One-line human-readable explanation of an assertion evaluation.

    Long values are truncated so explanations stay safe to log.
    """
    _, expected = evaluate_assertion(actual, assertion)
    target = assertion.path or "<document>"
    status = "satisfied" if passed else "not satisfied"
    return f"{target}: expected {expected}, actual {_short(actual)} ({status})"


class PolicyEngine:
    """Evaluates metadata documents against loaded policies (deploy-time gate)."""

    def __init__(self, policies: list[Policy]):
        self.policies = policies

    def evaluate(self, metadata: dict[str, Any]) -> list[EvaluationResult]:
        results: list[EvaluationResult] = []
        for policy in self.policies:
            outcomes: list[RuleOutcome] = []
            for rule in policy.rules:
                actual = resolve_path(metadata, rule.assert_.path)
                passed, expected = evaluate_assertion(actual, rule.assert_)
                outcomes.append(
                    RuleOutcome(
                        rule_id=rule.id,
                        passed=passed,
                        severity=rule.severity,
                        description=rule.description,
                        remediation=rule.remediation,
                        actual=actual,
                        expected=expected,
                    )
                )
            results.append(EvaluationResult(policy_name=policy.name, outcomes=outcomes))
        return results

    def gate(self, metadata: dict[str, Any]) -> tuple[bool, list[EvaluationResult]]:
        """Return (allowed_to_deploy, results). Any blocking failure denies deploy."""
        results = self.evaluate(metadata)
        allowed = all(r.passed for r in results)
        return allowed, results
