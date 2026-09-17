"""Policy evaluation engine.

Evaluates an AI system's metadata document against a set of declarative
policies. The metadata document is the infrastructure-layer view of the
system: model card presence, evaluation scores, dataset lineage, deployment
target, data-handling flags, etc.

The engine resolves dotted paths (``model.evaluations.bias_score``) against
nested dicts and evaluates the assertion operator declared in each rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .policy import Assertion, Policy, PolicyRule


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
            "blocking_failures": sum(1 for o in self.outcomes if not o.passed and o.severity == "block"),
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


def evaluate_assertion(actual: Any, assertion: Assertion) -> tuple[bool, Any]:
    """Evaluate one assertion. Returns (passed, expected_description)."""
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
        try:
            return (actual is not None and float(actual) >= float(assertion.gte), f">={assertion.gte}")
        except (TypeError, ValueError):
            return (False, f">={assertion.gte}")
    if assertion.lte is not None:
        try:
            return (actual is not None and float(actual) <= float(assertion.lte), f"<={assertion.lte}")
        except (TypeError, ValueError):
            return (False, f"<={assertion.lte}")
    return (True, None)


class PolicyEngine:
    """Evaluates metadata documents against loaded policies."""

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
