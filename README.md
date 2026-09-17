# ai-policy-guard

**Policy-as-Code for AI Systems: enforce governance at the infrastructure layer.**

Declare governance rules once in YAML — model cards, evaluation bars, data
lineage, PII handling, approved base models — and gate every deployment
through them in CI, just like you already do for containers and Terraform.

This is the companion open-source implementation of the article
[*Policy-as-Code for AI Systems: Governance at Infrastructure*](https://dzone.com/articles/policy-as-code-for-ai-systems-enforcing-governance)
(DZone).

## Why

AI governance usually lives in wikis and review meetings — discovered *after*
a model ships. `ai-policy-guard` moves it into the deployment path:

- **Declarative** — governance teams write YAML, not application code
- **Deterministic** — pure evaluation, no network calls, safe in air-gapped CI
- **Blocking** — `severity: block` rules fail the build; `warn` rules report

## Install

```bash
pip install ai-policy-guard
```

Or from source:

```bash
git clone https://github.com/anushamukka9/ai-policy-guard
cd ai-policy-guard
pip install -e ".[dev]"
```

## Quickstart

```bash
# Evaluate a model descriptor against the example policies
policy-guard check --policy policies/examples --metadata examples/model.json

# Machine-readable output for CI
policy-guard check --policy policies/examples --metadata examples/model.json --format json
```

Or in Python:

```python
from policy_guard.engine import PolicyEngine
from policy_guard.policy import load_policy_dir

policies = load_policy_dir("policies/examples")
engine = PolicyEngine(policies)
allowed, results = engine.gate(metadata_dict)
print("ALLOWED" if allowed else "BLOCKED")
```

See [`examples/quickstart.py`](examples/quickstart.py).

## Writing policies

```yaml
apiVersion: policyguard.ai/v1
kind: ModelGovernancePolicy
metadata:
  name: production-llm-governance
spec:
  rules:
    - id: model-card-required
      description: Every production model must ship a model card
      severity: block          # block | warn | info
      assert:
        path: model.card.exists
        equals: true
      remediation: Add model/card.md following the template in docs/.

    - id: bias-score-threshold
      description: Bias score must meet the bar (>= 0.85)
      severity: block
      assert:
        path: model.evaluations.bias_score
        gte: 0.85
```

Supported assertions: `equals`, `not_equals` (`notEquals`), `in`, `exists`,
`gte`, `lte` — evaluated against dotted paths into your metadata document
(e.g. `model.evaluations.bias_score`).

Two starter packs ship in [`policies/examples`](policies/examples):
`model-governance.yaml` and `data-lineage.yaml`.

## CI integration

```yaml
- name: AI governance gate
  run: |
    pip install ai-policy-guard
    policy-guard check --policy policies/ --metadata model.json
```

Exit code `1` blocks the pipeline when any `severity: block` rule fails.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design rationale
and extension points.

## Roadmap

- [ ] Rego/OPA export for teams already on Open Policy Agent
- [ ] Model-registry adapters (MLflow, Weights & Biases)
- [ ] VS Code extension surfacing policy results inline

Contributions welcome — open an issue describing the governance gate you need.

## License

MIT — see [LICENSE](LICENSE).
