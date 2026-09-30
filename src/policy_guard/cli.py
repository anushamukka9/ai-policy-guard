"""CLI: policy-guard check/test/validate/audit."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml

from .audit import read_audit_log
from .engine import PolicyEngine
from .policy import (
    PolicyValidationError,
    load_policy_dir,
    load_policy_file,
    validate_policy_dict,
)
from .testing import load_test_file, run_suite


def _load_policies(policy_path: str):
    p = Path(policy_path)
    if p.is_dir():
        return load_policy_dir(p)
    return [load_policy_file(p)]


@click.group()
def main() -> None:
    """Policy-as-Code for AI Systems: govern models at the infrastructure layer."""


@main.command("check")
@click.option(
    "--policy",
    "policy_path",
    required=True,
    type=click.Path(exists=True),
    help="Policy file or directory containing policy YAML files.",
)
@click.option(
    "--metadata",
    "metadata_path",
    required=True,
    type=click.Path(exists=True),
    help="JSON or YAML file describing the AI system under review.",
)
@click.option("--format", "out_format", type=click.Choice(["text", "json"]), default="text")
def check(policy_path: str, metadata_path: str, out_format: str) -> None:
    """Evaluate metadata against policies; exit 1 when a blocking rule fails."""
    policies = _load_policies(policy_path)

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
                click.echo(f"  [{mark}:{o.severity}] {o.rule_id} - {o.description}")
                if not o.passed:
                    click.echo(f"      actual={o.actual!r} expected={o.expected!r}")
                    if o.remediation:
                        click.echo(f"      fix: {o.remediation}")
        click.echo(f"\nDeployment {'ALLOWED' if allowed else 'BLOCKED'}")

    sys.exit(0 if allowed else 1)


@main.command("validate")
@click.option(
    "--policy",
    "policy_path",
    required=True,
    type=click.Path(exists=True),
    help="Policy file or directory containing policy YAML files.",
)
def validate(policy_path: str) -> None:
    """Validate policy files against the schema; exit 1 on any error."""
    p = Path(policy_path)
    files = sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")) if p.is_dir() else [p]
    failures = 0
    for f in files:
        with open(f, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        errors = validate_policy_dict(data)
        if errors:
            failures += 1
            click.echo(f"INVALID {f}")
            for e in errors:
                click.echo(f"  - {e}")
        else:
            click.echo(f"OK      {f}")
    if failures:
        click.echo(f"\n{failures} file(s) failed validation")
        sys.exit(1)
    click.echo("\nAll policy files are valid")


@main.command("test")
@click.option(
    "--policy",
    "policy_path",
    required=True,
    type=click.Path(exists=True),
    help="Policy file or directory containing policy YAML files.",
)
@click.option(
    "--tests",
    "tests_path",
    required=True,
    type=click.Path(exists=True),
    help="PolicyTest YAML file with test cases.",
)
def test_cmd(policy_path: str, tests_path: str) -> None:
    """Run policy test cases; exit 1 when any case fails."""
    try:
        policies = _load_policies(policy_path)
    except PolicyValidationError as exc:
        click.echo(f"Policy validation failed:\n{exc}", err=True)
        sys.exit(2)
    cases = load_test_file(tests_path)
    results, summary = run_suite(policies, cases)
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        click.echo(f"[{mark}] {r.name}")
        for d in r.diffs:
            click.echo(f"       {d}")
    click.echo(f"\n{summary['passed']}/{summary['total']} cases passed")
    sys.exit(0 if summary["failed"] == 0 else 1)


@main.command("audit")
@click.option(
    "--log",
    "log_path",
    required=True,
    type=click.Path(exists=True),
    help="JSONL audit log written by the guard.",
)
@click.option(
    "--verdict",
    type=click.Choice(["allow", "deny", "require_approval"]),
    default=None,
    help="Only show entries with this verdict.",
)
@click.option("--limit", type=int, default=20, help="Max entries to show.")
def audit_cmd(log_path: str, verdict: str | None, limit: int) -> None:
    """Print recent audit log entries, optionally filtered by verdict."""
    shown = 0
    for entry in read_audit_log(log_path):
        if entry.get("event") != "decision":
            continue
        if verdict and entry.get("verdict") != verdict:
            continue
        denied = ",".join(entry.get("denied_by") or [])
        extra = f" denied_by={denied}" if denied else ""
        click.echo(
            f"{entry.get('ts')} [{entry.get('verdict')}] "
            f"phase={entry.get('phase')}{extra} "
            f"fired={','.join(entry.get('fired_rules') or []) or '-'}"
        )
        shown += 1
        if shown >= limit:
            break
    if shown == 0:
        click.echo("No matching audit entries found")


if __name__ == "__main__":
    main()
