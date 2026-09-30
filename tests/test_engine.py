"""Unit tests for the policy engine."""

from policy_guard.engine import (
    PolicyEngine,
    describe_assertion,
    evaluate_assertion,
    resolve_path,
    set_path,
)
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


def test_evaluate_assertion_always():
    ok, _ = evaluate_assertion(None, Assertion(path="x", always=True))
    assert ok


def test_evaluate_assertion_not_equals_and_alias():
    ok, _ = evaluate_assertion("a", Assertion.from_dict({"path": "x", "not_equals": "b"}))
    assert ok
    ok, _ = evaluate_assertion("a", Assertion.from_dict({"path": "x", "notEquals": "a"}))
    assert not ok


def test_evaluate_assertion_contains():
    ok, _ = evaluate_assertion("hello world", Assertion(path="x", contains="world"))
    assert ok
    ok, _ = evaluate_assertion("hello", Assertion(path="x", contains="world"))
    assert not ok
    ok, _ = evaluate_assertion(["a", "b"], Assertion(path="x", contains="b"))
    assert ok
    ok, _ = evaluate_assertion("hello world", Assertion(path="x", not_contains="mars"))
    assert ok
    ok, _ = evaluate_assertion("hello world", Assertion(path="x", not_contains="world"))
    assert not ok


def test_evaluate_assertion_matches():
    ok, expected = evaluate_assertion("order 12345", Assertion(path="x", matches=r"\d+"))
    assert ok
    assert "matches" in expected
    ok, _ = evaluate_assertion("no digits", Assertion(path="x", matches=r"\d+"))
    assert not ok
    ok, _ = evaluate_assertion(123, Assertion(path="x", matches=r"\d+"))
    assert not ok
    ok, _ = evaluate_assertion("abc", Assertion(path="x", matches="(["))
    assert not ok  # invalid pattern fails closed


def test_evaluate_assertion_starts_ends_with():
    ok, _ = evaluate_assertion("hello", Assertion(path="x", startswith="he"))
    assert ok
    ok, _ = evaluate_assertion("hello", Assertion(path="x", startswith="lo"))
    assert not ok
    ok, _ = evaluate_assertion("hello", Assertion(path="x", endswith="lo"))
    assert ok
    ok, _ = evaluate_assertion("hello", Assertion(path="x", endswith="he"))
    assert not ok


def test_evaluate_assertion_length():
    ok, _ = evaluate_assertion("hello", Assertion(path="x", length_gte=3))
    assert ok
    ok, _ = evaluate_assertion("hi", Assertion(path="x", length_gte=3))
    assert not ok
    ok, _ = evaluate_assertion([1, 2], Assertion(path="x", length_lte=2))
    assert ok
    ok, _ = evaluate_assertion([1, 2, 3], Assertion(path="x", length_lte=2))
    assert not ok
    ok, _ = evaluate_assertion(42, Assertion(path="x", length_gte=1))
    assert not ok


def test_evaluate_assertion_gte_rejects_non_numeric():
    ok, _ = evaluate_assertion("not a number", Assertion(path="x", gte=0.5))
    assert not ok
    ok, _ = evaluate_assertion(None, Assertion(path="x", gte=0.5))
    assert not ok


def test_set_path():
    doc: dict = {}
    assert set_path(doc, "a.b.c", 1)
    assert doc == {"a": {"b": {"c": 1}}}
    assert not set_path({"a": 5}, "a.b", 1)


def test_describe_assertion_truncates_long_values():
    text = describe_assertion(Assertion(path="x", equals="y"), "z" * 200, False)
    assert len(text) < 200
    assert "not satisfied" in text
