# Architecture

`ai-policy-guard` enforces AI governance as code at the infrastructure layer —
the same place you already gate containers, IaC, and deployments.

```
                  ┌─────────────────────┐
                  │  model.json / YAML  │  infrastructure-layer view
                  │  (card, evals, data)│  of the AI system
                  └─────────┬───────────┘
                            │
                  ┌─────────▼───────────┐
                  │    PolicyEngine     │
                  │  resolve path →     │
                  │  evaluate assertion │
                  └─────────┬───────────┘
                            │
              ┌─────────────┼──────────────┐
              │             │              │
     policies/*.yaml   CLI / CI gate   GitHub Action
     (declarative)     (exit 1 blocks) (reusable)
```

## Design choices

- **Declarative YAML policies** — governance teams write rules without
  touching application code; versioned alongside infra.
- **Dotted-path assertions** — a small, auditable operator set (`equals`,
  `in`, `gte/lte`, `exists`) covers most governance gates while staying
  reviewable by non-engineers.
- **Severity tiers** — `block` denies deployment; `warn` surfaces in the
  report without blocking; `info` is documentary.
- **No network calls** — evaluation is pure and deterministic, safe to run
  in air-gapped CI.

## Extension points

- Custom operators: subclass the assertion evaluator in `engine.py`.
- New sources: any JSON/YAML producer (model registry, experiment tracker)
  can feed `--metadata`.
- Notifications: emit `check --format json` into your existing alerting.
