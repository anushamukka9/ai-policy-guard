"""Run the policy test suite: policies are code, so test them like code.

Usage: python examples/run_policy_tests.py
(Equivalent CLI: policy-guard test --policy policies/examples/inference-guard.yaml
                               --tests examples/policy-tests.yaml)
"""

from pathlib import Path

from policy_guard.policy import load_policy_file
from policy_guard.testing import load_test_file, run_suite

BASE = Path(__file__).resolve().parent.parent


def main() -> int:
    policies = [load_policy_file(BASE / "policies" / "examples" / "inference-guard.yaml")]
    cases = load_test_file(BASE / "examples" / "policy-tests.yaml")
    results, summary = run_suite(policies, cases)
    for r in results:
        print(f"[{'PASS' if r.passed else 'FAIL'}] {r.name}")
        for d in r.diffs:
            print(f"         {d}")
    print(f"\n{summary['passed']}/{summary['total']} cases passed")
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
