import json
from copy import deepcopy

import pytest


@pytest.fixture
def rule_document():
    from cloud_ir_lab.rules import DEFAULT_RULE_DIR

    path = DEFAULT_RULE_DIR / "repeated-auth-failure.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_packaged_rules_load_with_readable_metadata():
    from cloud_ir_lab.rules import load_rules

    rules = load_rules()
    assert len(rules) == 8
    assert len({rule.id for rule in rules}) == 8
    assert all(rule.name and rule.interpretation and rule.action and rule.notes for rule in rules)


@pytest.mark.parametrize(
    ("location", "value", "message"),
    [
        (("surprise",), True, "unsupported"),
        (("level",), "urgent", "level"),
        (("status",), [], "status"),
        (("logsource", "service"), "sysmon", "logsource"),
        (("detection", "condition"), "selection | count()", "condition"),
        (("detection", "unknown"), 1, "unsupported"),
        (("detection", "selection", "eventName|contains"), "Login", "unsupported"),
        (("detection", "selection", "eventName"), [], "selection"),
        (("detection", "selection", "eventSource"), 42, "selection"),
        (("detection", "parameters", "threshold"), True, "threshold"),
        (("detection", "parameters", "window_minutes"), 0, "window_minutes"),
        (("detection", "parameters", "extra"), "x", "parameters"),
        (("attack",), {"technique_id": "invalid", "technique": "x", "tactic": "x"}, "attack"),
        (("falsepositives",), [], "falsepositives"),
    ],
)
def test_rule_validation_reports_file_and_problem(tmp_path, rule_document, location, value, message):
    from cloud_ir_lab.rules import RuleError, load_rules

    target = rule_document
    for key in location[:-1]:
        target = target[key]
    target[location[-1]] = value
    (tmp_path / "bad-rule.json").write_text(json.dumps(rule_document), encoding="utf-8")
    with pytest.raises(RuleError, match=rf"bad-rule\.json.*{message}"):
        load_rules(tmp_path)


def test_duplicate_rule_ids_are_rejected(tmp_path, rule_document):
    from cloud_ir_lab.rules import RuleError, load_rules

    for name in ("first.json", "second.json"):
        (tmp_path / name).write_text(json.dumps(rule_document), encoding="utf-8")
    with pytest.raises(RuleError, match="duplicate rule"):
        load_rules(tmp_path)


@pytest.mark.parametrize("text", ["[", '{"id":"first","id":"second"}', "[]"])
def test_invalid_rule_json_is_rejected(tmp_path, text):
    from cloud_ir_lab.rules import RuleError, load_rules

    (tmp_path / "broken.json").write_text(text, encoding="utf-8")
    with pytest.raises(RuleError, match=r"broken\.json"):
        load_rules(tmp_path)


def test_missing_rule_directory_is_rejected(tmp_path):
    from cloud_ir_lab.rules import RuleError, load_rules

    with pytest.raises(RuleError, match="rule"):
        load_rules(tmp_path / "absent")


def test_empty_rule_directory_is_rejected(tmp_path):
    from cloud_ir_lab.rules import RuleError, load_rules

    with pytest.raises(RuleError, match="no rule files"):
        load_rules(tmp_path)


def test_changed_rule_threshold_changes_real_detection(tmp_path, synthetic_dir, rule_document):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events
    from cloud_ir_lab.rules import load_rules

    rule_document["detection"]["parameters"]["threshold"] = 2
    (tmp_path / "two-failures.json").write_text(json.dumps(rule_document), encoding="utf-8")
    events = load_events(synthetic_dir / "failed_logins.json")[:2]
    finding, = analyze(events, rules=load_rules(tmp_path))
    assert len(finding.evidence) == 2


def test_rule_selection_is_evaluated(tmp_path, synthetic_dir, rule_document):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events
    from cloud_ir_lab.rules import load_rules

    changed = deepcopy(rule_document)
    changed["detection"]["selection"]["eventName"] = "LabDifferentOperation"
    (tmp_path / "changed.json").write_text(json.dumps(changed), encoding="utf-8")
    assert analyze(load_events(synthetic_dir / "failed_logins.json"), rules=load_rules(tmp_path)) == []
