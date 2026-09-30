"""Tests for the inference-time guard: effects, redaction, rate limiting."""

import pytest

from policy_guard.audit import AuditLogger
from policy_guard.guard import (
    ApprovalRequired,
    InferenceGuard,
    PolicyDenied,
    RateLimiter,
    apply_redactions,
)
from policy_guard.policy import Assertion, Policy, PolicyRule, RateLimit


def make_rule(id, effect=None, assert_=None, **kwargs):
    return PolicyRule(
        id=id,
        description=f"rule {id}",
        effect=effect,
        assert_=assert_ or Assertion(path="request.x", equals=True),
        **kwargs,
    )


def guard_with(*rules):
    return InferenceGuard([Policy(name="p", rules=list(rules))])


def test_deny_effect_blocks():
    guard = guard_with(
        make_rule("no-x", effect="deny", assert_=Assertion(path="request.x", equals=True))
    )
    d = guard.evaluate_request({"x": True})
    assert d.verdict == "deny"
    assert d.denied_by == ["no-x"]
    assert "no-x" in d.fired_rules
    assert any("no-x" in r for r in d.reasons)


def test_no_fired_rules_allows():
    guard = guard_with(
        make_rule("no-x", effect="deny", assert_=Assertion(path="request.x", equals=True))
    )
    d = guard.evaluate_request({"x": False})
    assert d.verdict == "allow"
    assert d.fired_rules == []


def test_require_approval_effect():
    guard = guard_with(
        make_rule(
            "need-human",
            effect="require-approval",
            assert_=Assertion(path="request.risk", equals="high"),
        )
    )
    d = guard.evaluate_request({"risk": "high"})
    assert d.verdict == "require_approval"
    assert d.approval_by == ["need-human"]


def test_deny_beats_approval():
    guard = guard_with(
        make_rule(
            "need-human",
            effect="require-approval",
            assert_=Assertion(path="request.risk", equals="high"),
        ),
        make_rule("no-x", effect="deny", assert_=Assertion(path="request.x", equals=True)),
    )
    d = guard.evaluate_request({"risk": "high", "x": True})
    assert d.verdict == "deny"


def test_allow_effect_records_but_does_not_change_verdict():
    guard = guard_with(
        make_rule(
            "admin-ok", effect="allow", assert_=Assertion(path="request.user.role", equals="admin")
        )
    )
    d = guard.evaluate_request({"user": {"role": "admin"}})
    assert d.verdict == "allow"
    assert "admin-ok" in d.fired_rules


def test_warn_effect_records_warning_and_allows():
    guard = guard_with(
        make_rule("watch-it", effect="warn", assert_=Assertion(path="request.x", equals=True))
    )
    d = guard.evaluate_request({"x": True})
    assert d.verdict == "allow"
    assert any("watch-it" in w for w in d.warnings)


def test_legacy_block_rule_without_effect_denies_on_failure():
    rule = PolicyRule(
        id="card-required",
        severity="block",
        assert_=Assertion(path="model.card.exists", equals=True),
    )
    guard = InferenceGuard([Policy(name="p", rules=[rule])])
    d = guard.evaluate_request({"model": {"card": {"exists": False}}})
    assert d.verdict == "deny"
    assert d.denied_by == ["card-required"]


def test_legacy_warn_rule_without_effect_only_warns():
    rule = PolicyRule(
        id="lineage-note",
        severity="warn",
        assert_=Assertion(path="dataset.lineage.documented", equals=True),
    )
    guard = InferenceGuard([Policy(name="p", rules=[rule])])
    d = guard.evaluate_request({"dataset": {"lineage": {"documented": False}}})
    assert d.verdict == "allow"
    assert any("lineage-note" in w for w in d.warnings)


def test_redact_whole_field():
    rule = make_rule(
        "scrub-prompt",
        effect="redact",
        assert_=Assertion(path="request.prompt", contains="ssn"),
        redact_fields=["request.prompt"],
    )
    doc = {"request": {"prompt": "my ssn is 123"}}
    new_doc, redacted = apply_redactions(doc, rule)
    assert redacted == ["request.prompt"]
    assert new_doc["request"]["prompt"] == "[REDACTED]"
    assert doc["request"]["prompt"] == "my ssn is 123"  # original untouched


def test_redact_pattern_substring():
    rule = make_rule(
        "scrub-email",
        effect="redact",
        assert_=Assertion(path="request.prompt", contains="@"),
        redact_fields=["request.prompt"],
        redact_pattern=r"[\w.+-]+@[\w-]+\.[\w.]+",
    )
    doc = {"request": {"prompt": "mail me at ana@example.com today"}}
    new_doc, redacted = apply_redactions(doc, rule)
    assert redacted == ["request.prompt"]
    assert new_doc["request"]["prompt"] == "mail me at [REDACTED] today"


def test_redact_missing_field_is_skipped():
    rule = make_rule(
        "scrub",
        effect="redact",
        assert_=Assertion(path="request.prompt", contains="@"),
        redact_fields=["request.missing"],
    )
    _, redacted = apply_redactions({"request": {"prompt": "a@b.c"}}, rule)
    assert redacted == []


def test_redact_applies_before_function_runs():
    seen = {}

    guard = guard_with(
        make_rule(
            "scrub-email",
            effect="redact",
            assert_=Assertion(path="request.prompt", contains="@"),
            redact_fields=["request.prompt"],
            redact_pattern=r"[\w.+-]+@[\w-]+\.[\w.]+",
        )
    )

    @guard.protect()
    def generate(request: dict) -> dict:
        seen["prompt"] = request["prompt"]
        return {"text": "ok"}

    generate({"prompt": "hi ana@example.com"})
    assert seen["prompt"] == "hi [REDACTED]"


def test_rate_limiter_allows_then_denies():
    now = [1000.0]
    limiter = RateLimiter(clock=lambda: now[0])
    allowed, count = limiter.allow("u1", 2, 60)
    assert (allowed, count) == (True, 1)
    allowed, count = limiter.allow("u1", 2, 60)
    assert (allowed, count) == (True, 2)
    allowed, count = limiter.allow("u1", 2, 60)
    assert (allowed, count) == (False, 2)


def test_rate_limiter_window_slides():
    now = [1000.0]
    limiter = RateLimiter(clock=lambda: now[0])
    assert limiter.allow("u1", 1, 60)[0] is True
    assert limiter.allow("u1", 1, 60)[0] is False
    now[0] += 61
    assert limiter.allow("u1", 1, 60)[0] is True


def test_rate_limiter_keys_are_isolated():
    limiter = RateLimiter()
    assert limiter.allow("a", 1, 60)[0] is True
    assert limiter.allow("a", 1, 60)[0] is False
    assert limiter.allow("b", 1, 60)[0] is True


def test_rate_limit_rule_denies_over_quota():
    now = [2000.0]
    guard = InferenceGuard(
        [
            Policy(
                name="p",
                rules=[
                    make_rule(
                        "quota",
                        effect="rate-limit",
                        assert_=Assertion(path="request.user.tier", equals="free"),
                        rate_limit=RateLimit(
                            limit=2, window_seconds=60, key_path="request.user.id"
                        ),
                    )
                ],
            )
        ],
        rate_limiter=RateLimiter(clock=lambda: now[0]),
    )
    req = {"user": {"id": "u9", "tier": "free"}}
    assert guard.evaluate_request(req).verdict == "allow"
    assert guard.evaluate_request(req).verdict == "allow"
    d = guard.evaluate_request(req)
    assert d.verdict == "deny"
    assert d.denied_by == ["quota"]
    assert "rate limit exceeded" in d.reasons[0]


def test_rate_limit_rule_ignores_non_matching_requests():
    guard = guard_with(
        make_rule(
            "quota",
            effect="rate-limit",
            assert_=Assertion(path="request.user.tier", equals="free"),
            rate_limit=RateLimit(limit=1, window_seconds=60, key_path="request.user.id"),
        )
    )
    req = {"user": {"id": "u9", "tier": "pro"}}
    assert guard.evaluate_request(req).verdict == "allow"
    assert guard.evaluate_request(req).verdict == "allow"


def test_rate_limit_not_double_counted_in_response_phase():
    now = [3000.0]
    guard = InferenceGuard(
        [
            Policy(
                name="p",
                rules=[
                    make_rule(
                        "quota",
                        effect="rate-limit",
                        assert_=Assertion(path="request.user.tier", equals="free"),
                        rate_limit=RateLimit(
                            limit=1, window_seconds=60, key_path="request.user.id"
                        ),
                    )
                ],
            )
        ],
        rate_limiter=RateLimiter(clock=lambda: now[0]),
    )
    req = {"user": {"id": "u9", "tier": "free"}}
    assert guard.evaluate_request(req).verdict == "allow"
    # The response-phase evaluation must not consume a second token.
    d = guard.evaluate_response(req, {"text": "hi"})
    assert d.verdict == "allow"
    assert guard.evaluate_request(req).verdict == "deny"


def test_protect_decorator_denies():
    guard = guard_with(
        make_rule("no-x", effect="deny", assert_=Assertion(path="request.x", equals=True))
    )

    @guard.protect()
    def fn(request: dict) -> dict:
        return {"text": "unreachable"}

    with pytest.raises(PolicyDenied) as exc_info:
        fn({"x": True})
    assert exc_info.value.decision.verdict == "deny"


def test_protect_decorator_requires_approval():
    guard = guard_with(
        make_rule(
            "need-human",
            effect="require-approval",
            assert_=Assertion(path="request.risk", equals="high"),
        )
    )

    @guard.protect()
    def fn(request: dict) -> dict:
        return {"text": "unreachable"}

    with pytest.raises(ApprovalRequired):
        fn({"risk": "high"})


def test_protect_decorator_denies_on_response():
    guard = guard_with(
        make_rule("no-bad", effect="deny", assert_=Assertion(path="response.text", contains="bad"))
    )

    @guard.protect()
    def fn(request: dict) -> dict:
        return {"text": "this is bad"}

    with pytest.raises(PolicyDenied):
        fn({"prompt": "hi"})


def test_protect_decorator_passes_through_non_dict_response():
    guard = guard_with(
        make_rule("no-x", effect="deny", assert_=Assertion(path="request.x", equals=True))
    )

    @guard.protect()
    def fn(request: dict) -> str:
        return "plain string"

    assert fn({"x": False}) == "plain string"


def test_protect_decorator_rejects_bad_signature():
    guard = guard_with()

    @guard.protect()
    def fn(prompt: str) -> str:
        return prompt

    with pytest.raises(TypeError):
        fn("not a dict")


def test_decision_explain_and_dict():
    guard = guard_with(
        make_rule("no-x", effect="deny", assert_=Assertion(path="request.x", equals=True))
    )
    d = guard.evaluate_request({"x": True})
    text = d.explain()
    assert "DENY" in text
    assert "no-x" in text
    payload = d.to_dict()
    assert payload["verdict"] == "deny"
    assert payload["denied_by"] == ["no-x"]
    assert "latency_ms" in payload


def test_guard_logs_decisions_to_audit():
    entries = []
    guard = InferenceGuard(
        [
            Policy(
                name="p",
                rules=[
                    make_rule(
                        "no-x", effect="deny", assert_=Assertion(path="request.x", equals=True)
                    )
                ],
            )
        ],
        audit=AuditLogger(entries.append),
    )
    guard.evaluate_request({"x": True})
    assert len(entries) == 1
    assert entries[0]["event"] == "decision"
    assert entries[0]["verdict"] == "deny"
    # Payload is summarized: shapes only, never raw content.
    assert entries[0]["payload"] == {"request": {"x": True}}


def test_input_document_is_never_mutated():
    guard = guard_with(
        make_rule(
            "scrub",
            effect="redact",
            assert_=Assertion(path="request.prompt", contains="@"),
            redact_fields=["request.prompt"],
        )
    )
    request = {"prompt": "a@b.c"}
    guard.evaluate_request(request)
    assert request == {"prompt": "a@b.c"}
