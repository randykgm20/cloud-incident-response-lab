import json
from pathlib import Path

import pytest


@pytest.mark.parametrize("failure_stage", ["prepare", "publish"])
@pytest.mark.parametrize("existing", [False, True])
def test_report_failure_restores_prior_state(tmp_path, synthetic_dir, monkeypatch, failure_stage, existing):
    from cloud_ir_lab.cli import main

    output = tmp_path / "reports"
    output.mkdir()
    old = {"findings.json": b'{"old":true}\n', "incident-report.md": b"# Old report\n"}
    if existing:
        for name, content in old.items():
            (output / name).write_bytes(content)

    original_write = Path.write_text
    original_replace = Path.replace

    def fail_write(path, *args, **kwargs):
        if path.name == "incident-report.md" and path.parent.name.startswith(".report-"):
            raise OSError("Simulated report preparation failure")
        return original_write(path, *args, **kwargs)

    def fail_replace(path, target):
        if Path(target) == output / "incident-report.md":
            raise OSError("Simulated report publication failure")
        return original_replace(path, target)

    if failure_stage == "prepare":
        monkeypatch.setattr(Path, "write_text", fail_write)
    else:
        monkeypatch.setattr(Path, "replace", fail_replace)

    assert main(["analyze", str(synthetic_dir), "--output-dir", str(output)]) == 1
    for name, content in old.items():
        if existing:
            assert (output / name).read_bytes() == content
        else:
            assert not (output / name).exists()
    assert list(output.glob(".report-*")) == []


def test_report_text_escapes_rule_metadata(tmp_path, synthetic_dir):
    from cloud_ir_lab.cli import main
    from cloud_ir_lab.rules import DEFAULT_RULE_DIR

    rules = tmp_path / "rules"
    rules.mkdir()
    document = json.loads((DEFAULT_RULE_DIR / "unusual-source.json").read_text(encoding="utf-8"))
    document["title"] = "<img src='https://example.invalid/rule'>"
    document["description"] = "[click](https://example.invalid/rule)"
    (rules / "rule.json").write_text(json.dumps(document), encoding="utf-8")
    assert main([
        "analyze", str(synthetic_dir / "unusual_source.json"),
        "--rules-dir", str(rules), "--output-dir", str(tmp_path / "reports")
    ]) == 0
    markdown = (tmp_path / "reports/incident-report.md").read_text(encoding="utf-8")
    assert "<img" not in markdown
    assert "[click](" not in markdown


def test_deterministic_order_with_equal_timestamps_and_reversed_records(tmp_path, raw_event):
    from cloud_ir_lab.cli import main

    first = {**raw_event, "eventID": "lab-a", "sourceIPAddress": "203.0.113.77"}
    second = {
        **first, "eventID": "lab-b",
        "userIdentity": {"type": "Root", "arn": "arn:aws:iam::000000000000:root"},
    }
    for label, records in (("forward", [first, second]), ("reverse", [second, first, first])):
        source = tmp_path / f"{label}.json"
        source.write_text(json.dumps({"Records": records}), encoding="utf-8")
        assert main(["analyze", str(source), "--output-dir", str(tmp_path / label)]) == 0

    for name in ("findings.json", "incident-report.md"):
        assert (tmp_path / "forward" / name).read_bytes() == (tmp_path / "reverse" / name).read_bytes()
    report = json.loads((tmp_path / "forward/findings.json").read_text(encoding="utf-8"))
    assert [finding["rule_id"] for finding in report["findings"]] == [
        "unusual-source", "root-account-activity", "unusual-source",
    ]


def test_custom_invalid_rule_directory_returns_clear_command_error(tmp_path, synthetic_dir, capsys):
    from cloud_ir_lab.cli import main

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.json").write_text('{"id":"broken"}', encoding="utf-8")
    assert main([
        "analyze", str(synthetic_dir), "--rules-dir", str(rules),
        "--output-dir", str(tmp_path / "reports")
    ]) == 1
    assert "bad.json" in capsys.readouterr().err
    assert not (tmp_path / "reports").exists()


def test_report_symlink_cannot_overwrite_another_file(tmp_path, synthetic_dir, monkeypatch):
    from cloud_ir_lab.cli import main

    output = tmp_path / "reports"
    output.mkdir()
    destination = output / "findings.json"
    original = Path.is_symlink

    def reports_as_symlink(path):
        return path == destination or original(path)

    monkeypatch.setattr(Path, "is_symlink", reports_as_symlink)
    assert main(["analyze", str(synthetic_dir), "--output-dir", str(output)]) == 1
    assert not destination.exists()


@pytest.mark.parametrize("fixture", ["root_activity", "cross_user_access_key"])
def test_new_synthetic_scenarios_match(synthetic_dir, fixture):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events

    assert len(analyze(load_events(synthetic_dir / f"{fixture}.json"))) == 1


def test_new_normal_controls_remain_quiet(synthetic_dir):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events

    assert analyze(load_events(synthetic_dir / "normal_new_activity.json")) == []


@pytest.mark.parametrize("input_kind", ["config", "rule"])
def test_report_cannot_replace_configuration_inputs(tmp_path, synthetic_dir, input_kind, capsys):
    from cloud_ir_lab.cli import main
    from cloud_ir_lab.rules import DEFAULT_RULE_DIR

    path = tmp_path / "findings.json"
    if input_kind == "config":
        content = '{"schema_version":1,"approvals":[]}'
        extra = ["--config", str(path)]
    else:
        content = (DEFAULT_RULE_DIR / "unusual-source.json").read_text(encoding="utf-8")
        extra = ["--rules-dir", str(tmp_path)]
    path.write_text(content, encoding="utf-8")
    assert main([
        "analyze", str(synthetic_dir / "normal_activity.json"),
        "--output-dir", str(tmp_path), *extra
    ]) == 1
    assert "input" in capsys.readouterr().err.lower()
    assert path.read_text(encoding="utf-8") == content
