"""Policy definition and loading.

A policy is a declarative YAML document describing governance rules for an
AI system. Example:

    apiVersion: policyguard.ai/v1
    kind: ModelGovernancePolicy
    metadata:
      name: production-llm-governance
    spec:
      rules:
        - id: model-card-required
          description: Every production model must ship a model card
          severity: block
          assert:
            path: model.card.exists
            equals: true

Rules carry an optional ``effect`` for inference-time enforcement. When a
rule with an effect has its assertion satisfied, the rule "fires" and the
effect applies:

    - id: block-secret-leak
      effect: deny
      description: Model output must never contain API keys
      assert:
        path: response.text
        matches: "sk-[A-Za-z0-9]{20,}"

Supported effects: allow, deny, require-approval, rate-limit, redact, warn.
Rules without an effect keep the classic deploy-gate semantics driven by
``severity`` (block denies when the assertion fails).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITIES = ("block", "warn", "info")
EFFECTS = ("allow", "deny", "require-approval", "rate-limit", "redact", "warn")


class PolicyValidationError(ValueError):
    """Raised when a policy document fails schema or semantic validation."""


@dataclass
class Assertion:
    """A single assertion inside a rule."""

    path: str = ""
    always: bool = False
    equals: Any = None
    not_equals: Any = None
    in_list: list[Any] | None = None
    exists: bool | None = None
    gte: float | None = None
    lte: float | None = None
    contains: Any = None
    not_contains: Any = None
    matches: str | None = None
    startswith: str | None = None
    endswith: str | None = None
    length_gte: int | None = None
    length_lte: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Assertion:
        # Accept both not_equals and the camelCase notEquals alias.
        not_equals = data.get("not_equals", data.get("notEquals"))
        return cls(
            path=data.get("path", ""),
            always=bool(data.get("always", False)),
            equals=data.get("equals"),
            not_equals=not_equals,
            in_list=data.get("in"),
            exists=data.get("exists"),
            gte=data.get("gte"),
            lte=data.get("lte"),
            contains=data.get("contains"),
            not_contains=data.get("not_contains"),
            matches=data.get("matches"),
            startswith=data.get("startswith"),
            endswith=data.get("endswith"),
            length_gte=data.get("length_gte"),
            length_lte=data.get("length_lte"),
        )

    def operators(self) -> list[str]:
        """Names of the operators set on this assertion (for explanations)."""
        names = []
        if self.always:
            names.append("always")
        for name in (
            "equals",
            "not_equals",
            "in_list",
            "exists",
            "gte",
            "lte",
            "contains",
            "not_contains",
            "matches",
            "startswith",
            "endswith",
            "length_gte",
            "length_lte",
        ):
            if getattr(self, name) is not None:
                names.append(name)
        return names


@dataclass
class RateLimit:
    """Sliding-window quota attached to an effect: rate-limit rule."""

    limit: int = 0
    window_seconds: int = 60
    key_path: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> RateLimit | None:
        if not data:
            return None
        return cls(
            limit=int(data.get("limit", 0)),
            window_seconds=int(data.get("window_seconds", 60)),
            key_path=data.get("key_path", ""),
        )


@dataclass
class PolicyRule:
    id: str
    description: str = ""
    severity: str = "warn"  # block | warn | info
    assert_: Assertion = field(default_factory=Assertion)
    remediation: str = ""
    effect: str | None = None  # allow | deny | require-approval | rate-limit | redact | warn
    redact_fields: list[str] = field(default_factory=list)
    redact_pattern: str | None = None
    rate_limit: RateLimit | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyRule:
        return cls(
            id=data["id"],
            description=data.get("description", ""),
            severity=data.get("severity", "warn"),
            assert_=Assertion.from_dict(data.get("assert", {})),
            remediation=data.get("remediation", ""),
            effect=data.get("effect"),
            redact_fields=list(data.get("redact_fields", []) or []),
            redact_pattern=data.get("redact_pattern"),
            rate_limit=RateLimit.from_dict(data.get("rate_limit")),
        )


@dataclass
class Policy:
    name: str
    kind: str = "ModelGovernancePolicy"
    rules: list[PolicyRule] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        metadata = data.get("metadata", {})
        spec = data.get("spec", {})
        return cls(
            name=metadata.get("name", "unnamed-policy"),
            kind=data.get("kind", "ModelGovernancePolicy"),
            rules=[PolicyRule.from_dict(r) for r in spec.get("rules", [])],
            raw=data,
        )


def validate_policy_dict(data: dict[str, Any]) -> list[str]:
    """Return a list of validation errors for a raw policy document.

    Combines JSON Schema validation with semantic checks the schema cannot
    express (duplicate rule ids, effect-specific required fields).
    """
    from .schema import POLICY_SCHEMA

    errors: list[str] = []
    try:
        from jsonschema import Draft202012Validator

        validator = Draft202012Validator(POLICY_SCHEMA)
        for err in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
            location = "/".join(str(p) for p in err.path) or "<root>"
            errors.append(f"{location}: {err.message}")
    except ImportError:  # pragma: no cover - jsonschema is a hard dependency
        errors.append("jsonschema is required for policy validation")

    # Semantic checks.
    spec = data.get("spec", {}) if isinstance(data, dict) else {}
    rules = spec.get("rules", []) if isinstance(spec, dict) else []
    seen: set[str] = set()
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        rid = rule.get("id", f"rule[{i}]")
        if rid in seen:
            errors.append(f"spec/rules[{i}]: duplicate rule id '{rid}'")
        seen.add(rid)
        effect = rule.get("effect")
        if effect == "rate-limit":
            rl = rule.get("rate_limit") or {}
            if not isinstance(rl.get("limit"), int) or rl.get("limit", 0) <= 0:
                errors.append(
                    f"spec/rules[{i}] ('{rid}'): rate_limit.limit must be a positive integer"
                )
            if not isinstance(rl.get("window_seconds"), int) or rl.get("window_seconds", 0) <= 0:
                errors.append(
                    f"spec/rules[{i}] ('{rid}'): rate_limit.window_seconds must be a positive integer"
                )
        if effect == "redact" and not rule.get("redact_fields"):
            errors.append(f"spec/rules[{i}] ('{rid}'): effect 'redact' requires redact_fields")
    return errors


def load_policy_file(path: str | Path, validate: bool = True) -> Policy:
    """Load a single policy YAML file, validating it unless asked not to."""
    import yaml

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if validate:
        errors = validate_policy_dict(data)
        if errors:
            raise PolicyValidationError(
                f"Invalid policy file {path}:\n" + "\n".join(f"  - {e}" for e in errors)
            )
    return Policy.from_dict(data)


def load_policy_dir(directory: str | Path, validate: bool = True) -> list[Policy]:
    """Load every *.yaml / *.yml policy in a directory."""
    directory = Path(directory)
    policies: list[Policy] = []
    for pattern in ("*.yaml", "*.yml"):
        for file in sorted(directory.glob(pattern)):
            policies.append(load_policy_file(file, validate=validate))
    return policies
