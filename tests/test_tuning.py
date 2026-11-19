import json
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_tuning_is_narrow_and_keeps_evidence(tmp_path, capsys):
    from cloud_ir_lab.cli import main

    source = ROOT / "data/tuning/approved_activity.json"
    config = ROOT / "config/approved_activity.json"
    assert main(["analyze", str(source), "--output-dir", str(tmp_path / "before")]) == 0
    assert main([
        "analyze", str(source), "--config", str(config), "--output-dir", str(tmp_path / "after")
    ]) == 0
    before = json.loads((tmp_path / "before/findings.json").read_text(encoding="utf-8"))
    after = json.loads((tmp_path / "after/findings.json").read_text(encoding="utf-8"))
    assert before["finding_count"] == 4
    assert after["finding_count"] == 2
    assert after["suppressed_count"] == 2
    assert {finding["rule_id"] for finding in after["findings"]} == {"cloudtrail-disabled", "unusual-source"}
    active_unusual, = [finding for finding in after["findings"] if finding["rule_id"] == "unusual-source"]
    assert active_unusual["identity"].endswith("/lab-other")
    before_by_event = {
        (finding["rule_id"], finding["evidence"][0]["eventID"]): finding for finding in before["findings"]
    }
    for suppressed in after["suppressed_findings"]:
        original = before_by_event[(suppressed["rule_id"], suppressed["evidence"][0]["eventID"])]
        assert suppressed["evidence"] == original["evidence"]
        assert suppressed["suppression_reason"].startswith("Fictional change")
    markdown = (tmp_path / "after/incident-report.md").read_text(encoding="utf-8")
    assert "Suppressed findings" in markdown
    assert "LAB-CHANGE-001" in markdown
    assert "2 suppressed" in capsys.readouterr().out


@pytest.fixture
def config_document():
    return json.loads((ROOT / "config/approved_activity.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("rule_id", "unknown-rule", "unknown rule"),
        ("identity", "*", "identity"),
        ("source_ip", "203.0.113.0/24", "source_ip"),
        ("source_ip", [], "source_ip"),
        ("reason", "", "reason"),
        ("extra", True, "fields"),
    ],
)
def test_invalid_approval_is_rejected(tmp_path, config_document, field, value, message):
    from cloud_ir_lab.rules import load_rules
    from cloud_ir_lab.tuning import ConfigError, load_config

    config_document["approvals"][0][field] = value
    path = tmp_path / "bad-config.json"
    path.write_text(json.dumps(config_document), encoding="utf-8")
    with pytest.raises(ConfigError, match=rf"bad-config\.json.*{message}"):
        load_config(path, {rule.id for rule in load_rules()})


def test_duplicate_approval_is_rejected(tmp_path, config_document):
    from cloud_ir_lab.tuning import ConfigError, load_config

    config_document["approvals"].append(deepcopy(config_document["approvals"][0]))
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps(config_document), encoding="utf-8")
    with pytest.raises(ConfigError, match="duplicate approval"):
        load_config(path, {"unusual-source"})


@pytest.mark.parametrize(
    "document",
    [[], {"schema_version": True, "approvals": []}, {"schema_version": 1, "approvals": {}},
     {"schema_version": 2, "approvals": []}, {"schema_version": 1, "approvals": [], "extra": 1}],
)
def test_unsupported_config_is_rejected(tmp_path, document):
    from cloud_ir_lab.tuning import ConfigError, load_config

    path = tmp_path / "config.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path, {"unusual-source"})


def test_tuning_must_match_all_contributing_sources(synthetic_dir, tmp_path, config_document):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events, parse_event
    from cloud_ir_lab.tuning import apply_tuning, load_config

    events = load_events(synthetic_dir / "failed_logins.json")
    changed = {**events[0].raw, "sourceIPAddress": "192.0.2.10"}
    events[0] = parse_event(changed)
    finding, = analyze(events)
    approval = config_document["approvals"][0]
    approval.update(rule_id="repeated-auth-failure", identity=finding.identity, source_ip="198.51.100.23")
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(config_document), encoding="utf-8")
    active, suppressed = apply_tuning([finding], load_config(path, {finding.rule_id}))
    assert active == [finding]
    assert suppressed == []


def test_bad_config_returns_clear_cli_error_without_reports(tmp_path, synthetic_dir, capsys):
    from cloud_ir_lab.cli import main

    path = tmp_path / "config.json"
    path.write_text('{"schema_version":1,"schema_version":2,"approvals":[]}', encoding="utf-8")
    output = tmp_path / "reports"
    assert main([
        "analyze", str(synthetic_dir), "--config", str(path), "--output-dir", str(output)
    ]) == 1
    assert "duplicate field" in capsys.readouterr().err
    assert not output.exists()
