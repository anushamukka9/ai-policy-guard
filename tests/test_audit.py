"""Tests for audit logging: sinks, payload summarization, log reading."""

import json

from policy_guard.audit import AuditLogger, read_audit_log, summarize_value


def test_summarize_value_collapses_strings():
    assert summarize_value("hello") == "<str len=5>"
    assert summarize_value({"prompt": "secret text here"}) == {"prompt": "<str len=16>"}
    assert summarize_value({"a": {"b": "deep"}}) == {"a": {"b": "<str len=4>"}}
    assert summarize_value({"a": {"b": {"c": "deep"}}}) == {"a": {"b": "<dict keys=1>"}}


def test_summarize_value_keeps_scalars():
    assert summarize_value(True) is True
    assert summarize_value(42) == 42
    assert summarize_value(None) is None
    assert summarize_value([1, 2, 3]) == [1, 2, 3]


def test_file_sink_writes_jsonl(tmp_path):
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    logger.log("decision", {"verdict": "deny"})
    logger.log("decision", {"verdict": "allow"})
    logger.close()

    entries = list(read_audit_log(log))
    assert len(entries) == 2
    assert entries[0]["verdict"] == "deny"
    assert "ts" in entries[0]


def test_read_audit_log_skips_malformed_lines(tmp_path):
    log = tmp_path / "audit.jsonl"
    log.write_text('{"event": "decision"}\nnot json\n{"event": "decision"}\n')
    assert len(list(read_audit_log(log))) == 2


def test_callable_sink(tmp_path):
    entries = []
    logger = AuditLogger(entries.append)
    logger.log("decision", {"verdict": "allow"})
    assert len(entries) == 1
    assert entries[0]["event"] == "decision"


def test_none_sink_discards(capsys):
    logger = AuditLogger(None)
    logger.log("decision", {"verdict": "allow"})
    assert capsys.readouterr().out == ""


def test_log_decision_uses_decision_dict(tmp_path):
    from policy_guard.guard import Decision

    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    decision = Decision(verdict="deny", denied_by=["r1"])
    logger.log_decision(decision, {"request": {"prompt": "do not log me verbatim"}})
    logger.close()

    (entry,) = list(read_audit_log(log))
    assert entry["verdict"] == "deny"
    assert entry["denied_by"] == ["r1"]
    assert entry["payload"] == {"request": {"prompt": "<str len=22>"}}
    assert "do not log me verbatim" not in json.dumps(entry)
