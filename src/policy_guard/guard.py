"""Inference-time policy enforcement.

Where :class:`policy_guard.engine.PolicyEngine` gates deployments from
metadata documents, :class:`InferenceGuard` enforces policy on live
traffic: it evaluates an envelope document shaped like::

    {"request": {...}, "response": {...}}

against rules that declare an ``effect``. Rule semantics:

- ``effect: deny`` - the assertion fired, so the call is refused.
- ``effect: require-approval`` - the assertion fired, so a human must
  approve before the call proceeds.
- ``effect: rate-limit`` - the assertion fired, so the call counts against
  the rule's sliding-window quota (keyed by ``rate_limit.key_path``);
  exceeding the quota denies the call.
- ``effect: redact`` - the assertion fired, so the listed ``redact_fields``
  are scrubbed from the document before it continues. With
  ``redact_pattern``, only the matching substrings are replaced.
- ``effect: allow`` - the assertion fired; recorded as an explicit allow.
- ``effect: warn`` - the assertion fired; recorded as a warning.
- no ``effect`` - legacy deploy-gate semantics: a failed assertion with
  ``severity: block`` denies, ``warn``/``info`` are reported.

Every evaluation returns a :class:`Decision` carrying the verdict, the
rules that fired, human-readable reasons, and the (possibly redacted)
document. Decisions can be rendered with ``Decision.explain()`` and are
optionally written to an audit log on every evaluation.
"""

from __future__ import annotations

import copy
import re
import time
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable

from .audit import AuditLogger
from .engine import describe_assertion, evaluate_assertion, resolve_path, set_path
from .policy import Policy, PolicyRule


class PolicyDenied(Exception):
    """Raised when a guarded call is denied by policy."""

    def __init__(self, decision: Decision):
        super().__init__(f"Denied by policy: {decision.summary_line()}")
        self.decision = decision


class ApprovalRequired(Exception):
    """Raised when a guarded call needs human approval before proceeding."""

    def __init__(self, decision: Decision):
        super().__init__(f"Human approval required: {decision.summary_line()}")
        self.decision = decision


REDACTED = "[REDACTED]"


def apply_redactions(
    document: dict[str, Any], rule: PolicyRule
) -> tuple[dict[str, Any], list[str]]:
    """Apply a redact rule to a document copy.

    Returns (redacted_document, redacted_field_paths). With
    ``redact_pattern`` only the matching substrings inside string fields are
    replaced; otherwise the whole field value becomes "[REDACTED]".
    """
    doc = copy.deepcopy(document)
    redacted: list[str] = []
    pattern = None
    if rule.redact_pattern:
        try:
            pattern = re.compile(rule.redact_pattern)
        except re.error:
            pattern = None
    for field_path in rule.redact_fields:
        current = resolve_path(doc, field_path)
        if current is None:
            continue
        if pattern is not None and isinstance(current, str):
            new_value = pattern.sub(REDACTED, current)
        else:
            new_value = REDACTED
        if new_value != current and set_path(doc, field_path, new_value):
            redacted.append(field_path)
    return doc, redacted


class RateLimiter:
    """In-memory sliding-window rate limiter.

    ``allow`` returns True when the call fits inside the quota. State is a
    dict of key -> list of monotonic timestamps; entries outside the window
    are dropped on each check. The clock is injectable for deterministic
    tests. This is deliberately process-local: for multi-process or
    multi-host enforcement, back it with Redis or your rate-limit service.
    """

    def __init__(self, clock: Callable[[], float] | None = None):
        self._clock = clock or time.monotonic
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        """Return (allowed, current_count_in_window)."""
        now = self._clock()
        cutoff = now - window_seconds
        hits = [t for t in self._hits.get(key, []) if t > cutoff]
        allowed = len(hits) < limit
        if allowed:
            hits.append(now)
        self._hits[key] = hits
        return allowed, len(hits)

    def reset(self) -> None:
        self._hits.clear()


@dataclass
class Decision:
    """The outcome of one policy evaluation."""

    verdict: str  # allow | deny | require_approval
    reasons: list[str] = field(default_factory=list)
    fired_rules: list[str] = field(default_factory=list)
    denied_by: list[str] = field(default_factory=list)
    approval_by: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    redactions: list[str] = field(default_factory=list)
    document: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    phase: str = "request"

    def summary_line(self) -> str:
        bits = [f"verdict={self.verdict}"]
        if self.denied_by:
            bits.append("denied_by=" + ",".join(self.denied_by))
        if self.approval_by:
            bits.append("approval_by=" + ",".join(self.approval_by))
        if self.redactions:
            bits.append("redacted=" + ",".join(self.redactions))
        return " ".join(bits)

    def explain(self) -> str:
        """Multi-line human-readable explanation of this decision."""
        lines = [f"Decision: {self.verdict.upper()} (phase: {self.phase})"]
        if self.fired_rules:
            lines.append(f"Fired rules: {', '.join(self.fired_rules)}")
        else:
            lines.append("Fired rules: none")
        for reason in self.reasons:
            lines.append(f"  - {reason}")
        for warning in self.warnings:
            lines.append(f"  ! warning: {warning}")
        if self.redactions:
            lines.append(f"Redacted fields: {', '.join(self.redactions)}")
        lines.append(f"Evaluated in {self.latency_ms:.2f} ms")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "phase": self.phase,
            "reasons": self.reasons,
            "fired_rules": self.fired_rules,
            "denied_by": self.denied_by,
            "approval_by": self.approval_by,
            "warnings": self.warnings,
            "redactions": self.redactions,
            "latency_ms": round(self.latency_ms, 3),
        }


class InferenceGuard:
    """Enforces policies with effects against live request/response traffic."""

    def __init__(
        self,
        policies: list[Policy],
        audit: AuditLogger | None = None,
        rate_limiter: RateLimiter | None = None,
    ):
        self.policies = policies
        self.audit = audit
        self.rate_limiter = rate_limiter or RateLimiter()

    def evaluate_request(self, request: dict[str, Any]) -> Decision:
        """Evaluate the request half of the envelope."""
        return self._evaluate({"request": request}, phase="request")

    def evaluate_response(self, request: dict[str, Any], response: dict[str, Any]) -> Decision:
        """Evaluate the full envelope once a response exists."""
        return self._evaluate({"request": request, "response": response}, phase="response")

    def _evaluate(self, envelope: dict[str, Any], phase: str) -> Decision:
        start = time.perf_counter()
        document = copy.deepcopy(envelope)
        decision = Decision(verdict="allow", document=document, phase=phase)

        for policy in self.policies:
            for rule in policy.rules:
                self._apply_rule(rule, decision)

        if decision.denied_by:
            decision.verdict = "deny"
        elif decision.approval_by:
            decision.verdict = "require_approval"

        decision.document = document
        decision.latency_ms = (time.perf_counter() - start) * 1000.0

        if self.audit is not None:
            # The document is already redacted at this point; the payload
            # is summarized (shapes only, no content) before logging.
            self.audit.log_decision(decision, decision.document)
        return decision

    def _apply_rule(self, rule: PolicyRule, decision: Decision) -> None:
        document = decision.document
        actual = resolve_path(document, rule.assert_.path)
        passed, _ = evaluate_assertion(actual, rule.assert_)
        explanation = describe_assertion(rule.assert_, actual, passed)

        if rule.effect is None:
            # Legacy deploy-gate semantics: severity drives the outcome.
            if not passed:
                if rule.severity == "block":
                    decision.denied_by.append(rule.id)
                    decision.fired_rules.append(rule.id)
                    reason = f"blocked by rule '{rule.id}': {explanation}"
                    if rule.remediation:
                        reason += f" Fix: {rule.remediation}"
                    decision.reasons.append(reason)
                else:
                    decision.warnings.append(f"rule '{rule.id}': {explanation}")
            return

        # Effect rules fire when the assertion is satisfied.
        if not passed:
            return
        if rule.effect == "rate-limit" and decision.phase == "response":
            # Quota counts requests, not evaluations: the request phase
            # already accounted for this call, so do not consume twice.
            return
        decision.fired_rules.append(rule.id)

        if rule.effect == "deny":
            decision.denied_by.append(rule.id)
            reason = f"denied by rule '{rule.id}': {explanation}"
            if rule.remediation:
                reason += f" Fix: {rule.remediation}"
            decision.reasons.append(reason)
        elif rule.effect == "require-approval":
            decision.approval_by.append(rule.id)
            decision.reasons.append(f"approval required by rule '{rule.id}': {explanation}")
        elif rule.effect == "rate-limit":
            rl = rule.rate_limit
            if rl is None:  # validated at load time; stay safe anyway
                decision.warnings.append(f"rule '{rule.id}': rate-limit has no quota configured")
                return
            key = resolve_path(document, rl.key_path) if rl.key_path else "global"
            key = str(key) if key is not None else "global"
            allowed, count = self.rate_limiter.allow(key, rl.limit, rl.window_seconds)
            if allowed:
                decision.reasons.append(
                    f"rule '{rule.id}': within quota ({count}/{rl.limit} per "
                    f"{rl.window_seconds}s for key '{key}')"
                )
            else:
                decision.denied_by.append(rule.id)
                decision.reasons.append(
                    f"denied by rule '{rule.id}': rate limit exceeded "
                    f"({rl.limit} per {rl.window_seconds}s for key '{key}')"
                )
        elif rule.effect == "redact":
            redacted_doc, redacted = apply_redactions(document, rule)
            decision.document.clear()
            decision.document.update(redacted_doc)
            decision.redactions.extend(redacted)
            if redacted:
                decision.reasons.append(
                    f"rule '{rule.id}': redacted {', '.join(redacted)} ({explanation})"
                )
        elif rule.effect == "allow":
            decision.reasons.append(f"explicitly allowed by rule '{rule.id}': {explanation}")
        elif rule.effect == "warn":
            decision.warnings.append(f"rule '{rule.id}': {explanation}")

    def protect(self, request_arg: int = 0, request_kwarg: str = "request"):
        """Decorate a function so its calls are policy-guarded.

        The wrapped function must take the request document (a dict) as a
        positional argument (default: the first) or as the ``request``
        keyword argument, and return the response document (a dict).

        Pre-call, the request is evaluated: deny raises
        :class:`PolicyDenied`, require-approval raises
        :class:`ApprovalRequired`, and any redaction is applied to the
        request before the function runs. Post-call, the response is
        evaluated the same way and redactions are applied to it.
        """

        def decorator(fn: Callable):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                if request_arg < len(args) and isinstance(args[request_arg], dict):
                    request = args[request_arg]
                    arg_index: int | None = request_arg
                elif request_kwarg in kwargs and isinstance(kwargs[request_kwarg], dict):
                    request = kwargs[request_kwarg]
                    arg_index = None
                else:
                    raise TypeError(
                        "protect() expects the request document (a dict) as "
                        f"positional argument {request_arg} or keyword '{request_kwarg}'"
                    )

                pre = self.evaluate_request(request)
                if pre.verdict == "deny":
                    raise PolicyDenied(pre)
                if pre.verdict == "require_approval":
                    raise ApprovalRequired(pre)
                guarded_request = pre.document["request"]

                if arg_index is not None:
                    new_args = list(args)
                    new_args[arg_index] = guarded_request
                    new_kwargs = kwargs
                else:
                    new_args = list(args)
                    new_kwargs = dict(kwargs)
                    new_kwargs[request_kwarg] = guarded_request

                response = fn(*new_args, **new_kwargs)
                if not isinstance(response, dict):
                    return response

                post = self.evaluate_response(guarded_request, response)
                if post.verdict == "deny":
                    raise PolicyDenied(post)
                if post.verdict == "require_approval":
                    raise ApprovalRequired(post)
                return post.document["response"]

            return wrapper

        return decorator
