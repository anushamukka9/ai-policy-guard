"""CLI: policy-guard check --policy policies/ --metadata model.json"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml

from .engine import PolicyEngine
from .policy import load_policy_dir, load_policy_file


@click.group()
def main() -> None:
    """Policy-as-Code for AI Systems — govern models at the infrastructure layer."""


@main.command("check")
@click.option("--policy", "policy_path", required=True, type=click.Path(exists=True),
              help="Policy file or directory containing policy YAML files.")
@click.option("--metadata", "metadata_path", required=True, type=click.Path(exists=True),
              help="JSON or YAML file describing the AI system under review.")
@click.option("--format", "out_format", type=click.Choice(["text", "json"]), default="text")
def check(policy_path: str, metadata_path: str, out_format: str) -> None:
    """Evaluate metadata against policies; exit 1 when a blocking rule fails."""
    p = Path(policy_path)
    policies = load_policy_dir(p) if p.is_dir() else [load_policy_file(p)]

    with open(metadata_path, encoding="utf-8") as fh:
        if metadata_path.endswith((".yaml", ".yml")):
            metadata = yaml.safe_load(fh)
        else:
            metadata = json.load(fh)

    engine = PolicyEngine(policies)
    allowed, results = engine.gate(metadata)

    if out_format == "json":
        payload = {
            "allowed": allowed,
            "policies": [
                {
                    "policy": r.policy_name,
                    "summary": r.summary(),
                    "outcomes": [
                        {
                            "rule": o.rule_id,
                            "passed": o.passed,
                            "severity": o.severity,
                            "description": o.description,
                            "actual": o.actual,
                            "expected": o.expected,
                            "remediation": o.remediation,
                        }
                        for o in r.outcomes
                    ],
                }
                for r in results
            ],
        }
        click.echo(json.dumps(payload, indent=2, default=str))
    else:
        for r in results:
            click.echo(f"\nPolicy: {r.policy_name}  {r.summary()}")
            for o in r.outcomes:
                mark = "PASS" if o.passed else "FAIL"
                click.echo(f"  [{mark}:{o.severity}] {o.rule_id} — {o.description}")
                if not o.passed:
                    click.echo(f"      actual={o.actual!r} expected={o.expected!r}")
                    if o.remediation:
                        click.echo(f"      fix: {o.remediation}")
        click.echo(f"\nDeployment {'ALLOWED' if allowed else 'BLOCKED'}")

    sys.exit(0 if allowed else 1)


if __name__ == "__main__":
    main()
