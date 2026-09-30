"""Tests for policy schema and semantic validation."""

import textwrap
from pathlib import Path

import pytest
import yaml

from policy_guard.policy import (
    PolicyValidationError,
    load_policy_dir,
    load_policy_file,
    validate_policy_dict,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "policies" / "examples"


def write_policy(tmp_path, body: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(textwrap.dedent(body))
    return path


VALID = """\
apiVersion: policyguard.ai/v1
kind: ModelGovernancePolicy
metadata:
  name: p
spec:
  rules:
    - id: r1
      severity: block
      effect: deny
      assert: {path: request.x, equals: true}
      redact_fields: [request.x]
      rate_limit: {limit: 5, window_seconds: 60, key_path: request.user}
"""


def test_valid_policy_has_no_errors(tmp_path):
    assert validate_policy_dict(yaml.safe_load(VALID)) == []


def test_example_policies_validate():
    policies = load_policy_dir(EXAMPLES)
    assert len(policies) == 3
    for path in sorted(EXAMPLES.glob("*.yaml")):
        assert validate_policy_dict(yaml.safe_load(path.read_text())) == [], path.name


def test_rejects_bad_severity(tmp_path):
    doc = yaml.safe_load(VALID)
    doc["spec"]["rules"][0]["severity"] = "critical"
    assert validate_policy_dict(doc)


def test_rejects_unknown_assertion_operator(tmp_path):
    doc = yaml.safe_load(VALID)
    doc["spec"]["rules"][0]["assert"] = {"path": "request.x", "eqals": True}
    errors = validate_policy_dict(doc)
    assert errors


def test_rejects_duplicate_rule_ids():
    doc = yaml.safe_load(VALID)
    doc["spec"]["rules"].append({"id": "r1", "assert": {"always": True}})
    errors = validate_policy_dict(doc)
    assert any("duplicate rule id" in e for e in errors)


def test_rejects_rate_limit_without_quota():
    doc = yaml.safe_load(VALID)
    doc["spec"]["rules"][0]["effect"] = "rate-limit"
    doc["spec"]["rules"][0]["rate_limit"] = {"limit": 0, "window_seconds": 60}
    errors = validate_policy_dict(doc)
    assert any("limit" in e for e in errors)


def test_rejects_redact_without_fields():
    doc = yaml.safe_load(VALID)
    doc["spec"]["rules"][0]["effect"] = "redact"
    doc["spec"]["rules"][0].pop("redact_fields")
    errors = validate_policy_dict(doc)
    assert any("redact_fields" in e for e in errors)


def test_rejects_missing_required_keys():
    assert validate_policy_dict({"kind": "X"})


def test_load_policy_file_raises_on_invalid(tmp_path):
    path = write_policy(
        tmp_path,
        """\
        apiVersion: policyguard.ai/v1
        kind: X
        metadata: {name: p}
        spec:
          rules:
            - id: r1
              severity: bogus
              assert: {path: x}
        """,
    )
    with pytest.raises(PolicyValidationError):
        load_policy_file(path)


def test_load_policy_file_skips_validation_when_asked(tmp_path):
    path = write_policy(
        tmp_path,
        """\
        apiVersion: policyguard.ai/v1
        kind: X
        metadata: {name: p}
        spec:
          rules:
            - id: r1
              assert: {path: x}
        """,
    )
    # Missing nothing structural; validation would flag nothing here anyway,
    # but the flag must not raise for lenient callers.
    policy = load_policy_file(path, validate=False)
    assert policy.name == "p"
