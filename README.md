# ai-policy-guard

**Policy-as-Code for AI Systems: enforce governance at the infrastructure layer and at inference time.**

Declare governance rules once in YAML, then enforce them in two places:

1. **Deploy-time gate** - evaluate a model descriptor (model card, eval scores,
   dataset lineage, PII handling) in CI and block the release when a
   `severity: block` rule fails.
2. **Inference-time guard** - evaluate live requests and responses against
   rules with effects: `deny`, `require-approval`, `rate-limit`, `redact`,
   `warn`, `allow`. Scrub PII before it reaches the model, refuse secret
   leaks in output, hold high-risk actions for a human, all with an audit
   trail of every decision.

This is the companion open-source implementation of the article
[*Policy-as-Code for AI Systems: Governance at Infrastructure*](https://dzone.com/articles/policy-as-code-for-ai-systems-enforcing-governance)
(DZone).

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

Deploy-time gate:

```bash
# Evaluate a model descriptor against the example policies
policy-guard check --policy policies/examples --metadata examples/model.json

# Machine-readable output for CI
policy-guard check --policy policies/examples --metadata examples/model.json --format json
```

Inference-time guard:

```python
from policy_guard.guard import InferenceGuard, PolicyDenied
from policy_guard.policy import load_policy_file

guard = InferenceGuard([load_policy_file("policies/examples/inference-guard.yaml")])

decision = guard.evaluate_request({"prompt": "Summarize this.", "user": {"id": "u1"}})
print(decision.verdict)   # allow
print(decision.explain()) # which rules fired and why
```

Run the full demo: `python examples/inference_guard.py`

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
```

### Assertions

Assertions resolve a dotted path against the document and apply one operator:

| Operator | Meaning |
|---|---|
| `equals` / `not_equals` | exact (in)equality |
| `in` | value is a member of the list |
| `exists` | path is present (`true`) or absent (`false`) |
| `gte` / `lte` | numeric comparison |
| `contains` / `not_contains` | substring (strings) or membership (lists) |
| `matches` | regex search on a string |
| `startswith` / `endswith` | string prefix/suffix |
| `length_gte` / `length_lte` | length of a string or list |
| `always` | always satisfied (useful for default-deny catch-alls) |

### Effects (inference-time)

When a rule declares an `effect`, the rule *fires* when its assertion is
satisfied, and the effect applies:

| Effect | Behavior |
|---|---|
| `deny` | refuse the call; raises `PolicyDenied` in the decorator |
| `require-approval` | hold for a human; raises `ApprovalRequired` |
| `rate-limit` | count the call against a sliding-window quota; over quota denies |
| `redact` | scrub `redact_fields` (whole value, or `redact_pattern` substrings) |
| `warn` | record a warning, still allow |
| `allow` | record an explicit allow |

```yaml
    - id: block-secret-leak
      effect: deny
      description: Model output must never contain API keys
      assert:
        path: response.text
        matches: "sk-[A-Za-z0-9]{20,}"
      remediation: Rotate the exposed key and review the retrieval context.

    - id: free-tier-rate-limit
      effect: rate-limit
      assert:
        path: request.user.tier
        equals: free
      rate_limit:
        limit: 5
        window_seconds: 60
        key_path: request.user.id

    - id: redact-emails-in-request
      effect: redact
      assert:
        path: request.prompt
        matches: "[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\\.[A-Za-z0-9-.]+"
      redact_fields: [request.prompt]
      redact_pattern: "[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\\.[A-Za-z0-9-.]+"
```

Rules without an `effect` keep the classic gate semantics: a failed
assertion with `severity: block` denies, `warn`/`info` are reported.

Starter packs in [`policies/examples`](policies/examples):
`model-governance.yaml` and `data-lineage.yaml` (deploy-time),
`inference-guard.yaml` (inference-time).

Validate any policy file before shipping it:

```bash
policy-guard validate --policy policies/
```

## Guarding a function

```python
guard = InferenceGuard(policies, audit=AuditLogger("decisions.jsonl"))

@guard.protect()
def generate(request: dict) -> dict:
    # request arrives here already redacted; return the response document
    return {"text": call_the_model(request["prompt"])}

try:
    generate({"prompt": "Summarize this.", "user": {"id": "u1"}})
except PolicyDenied as exc:
    print(exc.decision.explain())
except ApprovalRequired as exc:
    route_to_human_review(exc.decision)
```

The decorator evaluates the request before the call (deny and approval raise;
redactions are applied to the request first) and the response after the call.
For non-decorator use, call `guard.evaluate_request(request)` and
`guard.evaluate_response(request, response)` directly. A `Decision` carries
the verdict, fired rule ids, human-readable reasons, redacted field paths,
and `explain()` renders the whole thing as text.

## Audit logging

Pass an `AuditLogger` to the guard and every decision is appended to a JSONL
trail. Payloads are summarized, never stored verbatim: strings become
`"<str len=N>"`, so prompts, outputs, and PII never land in the log.

```bash
# Inspect recent decisions
policy-guard audit --log decisions.jsonl
policy-guard audit --log decisions.jsonl --verdict deny --limit 50
```

## Testing policies

Policies are code; test them like code. Write cases in a `PolicyTest` file
(see [`examples/policy-tests.yaml`](examples/policy-tests.yaml)) and run:

```bash
policy-guard test --policy policies/examples/inference-guard.yaml \
                  --tests examples/policy-tests.yaml
```

`expect` supports `verdict` (`allow` | `deny` | `require_approval`), `fired`
(rule ids that must have fired), and `redactions` (fields that must have been
scrubbed). `repeat: N` re-runs a case against a fresh guard, which is how you
test rate-limit rules.

## API reference

- `policy_guard.policy` - `Policy`, `PolicyRule`, `Assertion`, `RateLimit`,
  `load_policy_file`, `load_policy_dir`, `validate_policy_dict`,
  `PolicyValidationError`
- `policy_guard.engine` - `PolicyEngine` (deploy-time gate), `resolve_path`,
  `set_path`, `evaluate_assertion`, `describe_assertion`
- `policy_guard.guard` - `InferenceGuard`, `Decision`, `RateLimiter`,
  `PolicyDenied`, `ApprovalRequired`, `apply_redactions`
- `policy_guard.audit` - `AuditLogger`, `read_audit_log`, `summarize_value`
- `policy_guard.testing` - `load_test_file`, `run_case`, `run_suite`,
  `PolicyTestCase`

## Examples

- [`examples/quickstart.py`](examples/quickstart.py) - deploy-time gate in Python
- [`examples/inference_guard.py`](examples/inference_guard.py) - inference guard
  end to end: allow, redact, deny, rate limit, approval, decorator, audit trail
- [`examples/run_policy_tests.py`](examples/run_policy_tests.py) - run the
  policy test suite from Python
- [`examples/policy-tests.yaml`](examples/policy-tests.yaml) - test cases for
  the example inference policy

## Production notes

- Evaluation is pure and deterministic: no network calls, safe in air-gapped CI.
- The built-in `RateLimiter` is process-local and in-memory. For multi-process
  or multi-host enforcement, front it with Redis or your rate-limit service.
- `require-approval` raises; it does not queue. Wire `ApprovalRequired` to your
  human-review queue (ticket system, Slack, etc.).
- Audit logs summarize payloads, but rule descriptions and reasons can still
  name fields. Treat the log as sensitive and set retention accordingly.
- Keep policies in version control next to the infrastructure they govern and
  run `policy-guard validate` plus `policy-guard test` in CI.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design rationale
and extension points.

## Roadmap

- [ ] Rego/OPA export for teams already on Open Policy Agent
- [ ] Model-registry adapters (MLflow, Weights & Biases)
- [ ] VS Code extension surfacing policy results inline

Contributions welcome - open an issue describing the governance gate you need.

## License

MIT - see [LICENSE](LICENSE).
