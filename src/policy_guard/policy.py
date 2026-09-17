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
"""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Assertion:
    """A single assertion inside a rule."""

    path: str = ""
    equals: Any = None
    not_equals: Any = None
    in_list: list[Any] | None = None
    exists: bool | None = None
    gte: float | None = None
    lte: float | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Assertion":
        return cls(
            path=data.get("path", ""),
            equals=data.get("equals"),
            not_equals=data.get("not_equals"),
            in_list=data.get("in"),
            exists=data.get("exists"),
            gte=data.get("gte"),
            lte=data.get("lte"),
        )


@dataclass
class PolicyRule:
    id: str
    description: str = ""
    severity: str = "warn"  # block | warn | info
    assert_: Assertion = field(default_factory=Assertion)
    remediation: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyRule":
        return cls(
            id=data["id"],
            description=data.get("description", ""),
            severity=data.get("severity", "warn"),
            assert_=Assertion.from_dict(data.get("assert", {})),
            remediation=data.get("remediation", ""),
        )


@dataclass
class Policy:
    name: str
    kind: str = "ModelGovernancePolicy"
    rules: list[PolicyRule] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        metadata = data.get("metadata", {})
        spec = data.get("spec", {})
        return cls(
            name=metadata.get("name", "unnamed-policy"),
            kind=data.get("kind", "ModelGovernancePolicy"),
            rules=[PolicyRule.from_dict(r) for r in spec.get("rules", [])],
            raw=data,
        )


def load_policy_file(path: str | Path) -> Policy:
    """Load a single policy YAML file."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return Policy.from_dict(data)


def load_policy_dir(directory: str | Path) -> list[Policy]:
    """Load every *.yaml / *.yml policy in a directory."""
    directory = Path(directory)
    policies: list[Policy] = []
    for pattern in ("*.yaml", "*.yml"):
        for file in sorted(directory.glob(pattern)):
            policies.append(load_policy_file(file))
    return policies
