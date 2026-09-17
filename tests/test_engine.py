"""Unit tests for the policy engine."""

from policy_guard.engine import PolicyEngine, evaluate_assertion, resolve_path
from policy_guard.policy import Assertion, Policy, PolicyRule


def make_policy() -> Policy:
    return Policy(
        name="test-policy",
        rules=[
            PolicyRule(
                id="card-required",
                description="model card required",
                severity="block",
                assert_=Assertion(path="model.card.exists", equals=True),
            ),
            PolicyRule(
                id="bias-threshold",
                description="bias bar",
                severity="block",
                assert_=Assertion(path="model.evaluations.bias_score", gte=0.85),
            ),
        ],
    )


def test_resolve_path():
    doc = {"a": {"b": {"c": 42}}}
    assert resolve_path(doc, "a.b.c") == 42
    assert resolve_path(doc, "a.b.missing") is None
    assert resolve_path({}, "x") is None


def test_evaluate_assertion_equals():
    ok, _ = evaluate_assertion(True, Assertion(path="x", equals=True))
    assert ok
    ok, _ = evaluate_assertion(False, Assertion(path="x", equals=True))
    assert not ok


def test_evaluate_assertion_gte():
    ok, _ = evaluate_assertion(0.9, Assertion(path="x", gte=0.85))
    assert ok
    ok, _ = evaluate_assertion(0.5, Assertion(path="x", gte=0.85))
    assert not ok


def test_gate_allows_compliant_model():
    engine = PolicyEngine([make_policy()])
    metadata = {"model": {"card": {"exists": True}, "evaluations": {"bias_score": 0.9}}}
    allowed, results = engine.gate(metadata)
    assert allowed
    assert results[0].summary()["failed"] == 0


def test_gate_blocks_noncompliant_model():
    engine = PolicyEngine([make_policy()])
    metadata = {"model": {"card": {"exists": False}, "evaluations": {"bias_score": 0.5}}}
    allowed, results = engine.gate(metadata)
    assert not allowed
    assert results[0].summary()["blocking_failures"] == 2
