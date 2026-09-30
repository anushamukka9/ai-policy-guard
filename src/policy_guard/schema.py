"""JSON Schema for policy documents.

Validates the shape of a policy YAML file: required top-level keys, rule
fields, severity/effect enums, assertion operators, and the effect-specific
blocks (rate_limit, redact_fields). Semantic checks that the schema cannot
express (duplicate rule ids, positive quota values) live in
``policy.validate_policy_dict``.
"""

from __future__ import annotations

from typing import Any

ASSERTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
        "always": {"type": "boolean"},
        "equals": True,
        "not_equals": True,
        "notEquals": True,
        "in": {"type": "array"},
        "exists": {"type": "boolean"},
        "gte": {"type": "number"},
        "lte": {"type": "number"},
        "contains": True,
        "not_contains": True,
        "matches": {"type": "string"},
        "startswith": {"type": "string"},
        "endswith": {"type": "string"},
        "length_gte": {"type": "integer", "minimum": 0},
        "length_lte": {"type": "integer", "minimum": 0},
    },
    "additionalProperties": False,
}

RULE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["id", "assert"],
    "properties": {
        "id": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "severity": {"enum": ["block", "warn", "info"]},
        "effect": {"enum": ["allow", "deny", "require-approval", "rate-limit", "redact", "warn"]},
        "assert": ASSERTION_SCHEMA,
        "remediation": {"type": "string"},
        "redact_fields": {"type": "array", "items": {"type": "string"}},
        "redact_pattern": {"type": "string"},
        "rate_limit": {
            "type": "object",
            "required": ["limit", "window_seconds"],
            "properties": {
                "limit": {"type": "integer"},
                "window_seconds": {"type": "integer"},
                "key_path": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}

POLICY_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["apiVersion", "kind", "metadata", "spec"],
    "properties": {
        "apiVersion": {"type": "string"},
        "kind": {"type": "string"},
        "metadata": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "description": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "spec": {
            "type": "object",
            "required": ["rules"],
            "properties": {
                "rules": {"type": "array", "items": RULE_SCHEMA},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}
