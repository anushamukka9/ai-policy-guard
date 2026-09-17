"""Quickstart: evaluate a model descriptor against the example policies."""

import json
from pathlib import Path

from policy_guard.engine import PolicyEngine
from policy_guard.policy import load_policy_dir

BASE = Path(__file__).resolve().parent.parent

metadata = {
    "model": {
        "card": {"exists": True},
        "evaluations": {"suite_complete": True, "bias_score": 0.91},
        "data": {"pii_handling": "redacted"},
        "base_model": {"approved": True},
    },
    "dataset": {
        "license": "apache-2.0",
        "lineage": {"documented": True},
        "retention_days": 365,
    },
}

policies = load_policy_dir(BASE / "policies" / "examples")
engine = PolicyEngine(policies)
allowed, results = engine.gate(metadata)

for r in results:
    print(f"\nPolicy: {r.policy_name} {r.summary()}")
    for o in r.outcomes:
        print(f"  [{'PASS' if o.passed else 'FAIL'}:{o.severity}] {o.rule_id}")

print(f"\nDeployment {'ALLOWED' if allowed else 'BLOCKED'}")
