"""Tests for the policy testing framework."""

import textwrap

import pytest

from policy_guard.policy import Assertion, Policy, PolicyRule
from policy_guard.testing import (
    PolicyTestCase,
    load_test_file,
    run_case,
    run_suite,
)


def deny_policy():
    return [
        Policy(
            name="p",
            rules=[
                PolicyRule(
                    id="no-x",
                    effect="deny",
                    assert_=Assertion(path="request.x", equals=True),
                )
            ],
        )
    ]


def test_run_case_pass():
    case = PolicyTestCase(
        name="x blocks",
        request={"x": True},
        expect_verdict="deny",
        expect_fired=["no-x"],
    )
    result = run_case(deny_policy(), case)
    assert result.passed
    assert result.diffs == []


def test_run_case_detects_wrong_verdict():
    case = PolicyTestCase(name="oops", request={"x": True}, expect_verdict="allow")
    result = run_case(deny_policy(), case)
    assert not result.passed
    assert any("verdict" in d for d in result.diffs)


def test_run_case_detects_missing_fired_rule():
    case = PolicyTestCase(
        name="oops",
        request={"x": True},
        expect_verdict="deny",
        expect_fired=["nope"],
    )
    result = run_case(deny_policy(), case)
    assert not result.passed
    assert any("nope" in d for d in result.diffs)


def test_run_case_repeat_uses_last_run():
    from policy_guard.policy import RateLimit

    policies = [
        Policy(
            name="p",
            rules=[
                PolicyRule(
                    id="quota",
                    effect="rate-limit",
                    assert_=Assertion(path="request.tier", equals="free"),
                    rate_limit=RateLimit(limit=2, window_seconds=60, key_path="request.user"),
                )
            ],
        )
    ]
    case = PolicyTestCase(
        name="limited",
        request={"tier": "free", "user": "u1"},
        expect_verdict="deny",
        expect_fired=["quota"],
        repeat=3,
    )
    result = run_case(policies, case)
    assert result.passed


def test_run_suite_summary():
    cases = [
        PolicyTestCase(name="ok", request={"x": False}, expect_verdict="allow"),
        PolicyTestCase(name="bad", request={"x": True}, expect_verdict="allow"),
    ]
    results, summary = run_suite(deny_policy(), cases)
    assert summary == {"total": 2, "passed": 1, "failed": 1}
    assert [r.name for r in results] == ["ok", "bad"]


def test_load_test_file(tmp_path):
    path = tmp_path / "tests.yaml"
    path.write_text(
        textwrap.dedent(
            """\
            apiVersion: policyguard.ai/v1
            kind: PolicyTest
            metadata:
              name: t
            cases:
              - name: first
                request: {x: true}
                expect: {verdict: deny, fired: [no-x]}
              - name: second
                request: {x: false}
                response: {text: hi}
                repeat: 2
                expect: {verdict: allow}
            """
        )
    )
    cases = load_test_file(path)
    assert len(cases) == 2
    assert cases[0].name == "first"
    assert cases[0].expect_verdict == "deny"
    assert cases[0].expect_fired == ["no-x"]
    assert cases[1].response == {"text": "hi"}
    assert cases[1].repeat == 2


def test_load_test_file_rejects_wrong_kind(tmp_path):
    path = tmp_path / "tests.yaml"
    path.write_text("kind: SomethingElse\ncases: []\n")
    with pytest.raises(ValueError):
        load_test_file(path)
