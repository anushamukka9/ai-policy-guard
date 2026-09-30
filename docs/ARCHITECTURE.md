# Architecture

`ai-policy-guard` enforces AI governance as code in two places: at deploy
time, where a metadata document is gated in CI, and at inference time,
where live requests and responses are evaluated against rules with effects.

```
Deploy-time gate
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

Inference-time guard
                  ┌─────────────────────────┐
                  │ {"request": {...},      │
                  │  "response": {...}}     │  envelope document
                  └────────────┬────────────┘
                               │
                  ┌────────────▼────────────┐
                  │    InferenceGuard       │
                  │  rules with effects:    │
                  │  deny / require-        │
                  │  approval / rate-limit /│
                  │  redact / warn / allow  │
                  └────────────┬────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
        Decision +        JSONL audit      @guard.protect()
        explanation       trail            decorator
```

## Design choices

- **Declarative YAML policies** - governance teams write rules without
  touching application code; versioned alongside infra.
- **Dotted-path assertions** - a small, auditable operator set (`equals`,
  `in`, `gte/lte`, `exists`, `matches`, `contains`, string and length
  operators) covers most governance gates while staying reviewable by
  non-engineers.
- **Effects, not just severities** - deploy-time rules use `severity`
  (`block` denies, `warn`/`info` report); inference-time rules declare an
  `effect` so the same policy language expresses refusal, human approval,
  quotas, and redaction.
- **Decisions are explainable** - every evaluation returns which rules fired
  and one-line reasons with truncated values, so an operator can see exactly
  why a call was refused without dumping payloads.
- **Audit by default** - attach an `AuditLogger` and every decision lands in
  a JSONL trail with payloads summarized (shapes, never content).
- **No network calls** - evaluation is pure and deterministic, safe to run
  in air-gapped CI and on the hot path.

## Key behaviors

- **Redaction precedes enforcement input**: redact rules rewrite the document
  before later rules see it and before the guarded function runs, so a deny
  rule never observes the raw PII.
- **Rate limits count requests, not evaluations**: quota is consumed in the
  request phase only, so the decorator's pre/post evaluations cost one token
  per call. The limiter is process-local by design; bring Redis for
  multi-host setups.
- **Fail closed on bad patterns**: an invalid regex in `matches` or
  `redact_pattern` evaluates to "no match" rather than raising.
- **Policies are validated at load**: JSON Schema shape plus semantic checks
  (unique rule ids, positive quotas, `redact_fields` present for redact
  rules). `policy-guard validate` runs the same checks in CI.

## Extension points

- Custom operators: extend the assertion evaluator in `engine.py`.
- New sources: any JSON/YAML producer (model registry, experiment tracker)
  can feed `--metadata`.
- Notifications: emit `check --format json` into your existing alerting.
- New effects: add a branch in `InferenceGuard._apply_rule` and a row in the
  effect table; decisions and audit pick it up automatically.
- Policy tests: `policy-guard test` runs `PolicyTest` YAML files, so policy
  changes get the same CI treatment as code changes.
