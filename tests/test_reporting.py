import json


def test_command_writes_structured_and_readable_reports(tmp_path, synthetic_dir, capsys):
    from cloud_ir_lab.cli import main

    assert main(["analyze", str(synthetic_dir), "--output-dir", str(tmp_path)]) == 0
    summary = capsys.readouterr().out
    assert "15 events analyzed | 8 findings" in summary

    report = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert report["schema_version"] == 1
    assert report["event_count"] == 15
    assert report["finding_count"] == 8
    first = report["findings"][0]
    assert first["timestamp"] == "2026-01-15T14:09:00Z"
    assert first["evidence"][0]["responseElements"] == {"ConsoleLogin": "Failure"}
    assert first["interpretation"]
    assert first["attack"]["technique_id"] == "T1110.001"

    markdown = (tmp_path / "incident-report.md").read_text(encoding="utf-8")
    assert markdown.startswith("# Synthetic cloud incident report")
    assert "Analyst interpretation" in markdown
    assert "Observed evidence" in markdown
    assert "Recommended analyst action" in markdown
    assert '"ConsoleLogin": "Failure"' in markdown


def test_command_reports_clean_activity(tmp_path, synthetic_dir, capsys):
    from cloud_ir_lab.cli import main

    source = synthetic_dir / "normal_activity.json"
    assert main(["analyze", str(source), "--output-dir", str(tmp_path)]) == 0
    assert "3 events analyzed | 0 findings" in capsys.readouterr().out
    report = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert report["findings"] == []
    assert "No findings" in (tmp_path / "incident-report.md").read_text(encoding="utf-8")


def test_command_rejects_an_invalid_input_before_writing_reports(tmp_path, capsys):
    from cloud_ir_lab.cli import main

    path = tmp_path / "invalid.json"
    path.write_text("not JSON", encoding="utf-8")
    output = tmp_path / "reports"
    assert main(["analyze", str(path), "--output-dir", str(output)]) == 1
    assert "invalid.json" in capsys.readouterr().err
    assert not output.exists()


def test_command_reports_output_filesystem_error(tmp_path, synthetic_dir, capsys):
    from cloud_ir_lab.cli import main

    occupied = tmp_path / "occupied"
    occupied.touch()
    assert main(["analyze", str(synthetic_dir), "--output-dir", str(occupied)]) == 1
    assert "Could not save reports" in capsys.readouterr().err


def test_command_preserves_prior_json_when_markdown_destination_is_blocked(
    tmp_path, synthetic_dir, capsys
):
    from cloud_ir_lab.cli import main

    json_report = tmp_path / "findings.json"
    json_report.write_text('{"previous_run": true}', encoding="utf-8")
    (tmp_path / "incident-report.md").mkdir()
    assert main(["analyze", str(synthetic_dir), "--output-dir", str(tmp_path)]) == 1
    assert "Could not save reports" in capsys.readouterr().err
    assert json_report.read_text(encoding="utf-8") == '{"previous_run": true}'


def test_command_can_override_known_source(tmp_path, synthetic_dir):
    from cloud_ir_lab.cli import main

    args = [
        "analyze", str(synthetic_dir / "unusual_source.json"),
        "--output-dir", str(tmp_path), "--known-source", "203.0.113.77",
    ]
    assert main(args) == 0
    report = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert report["finding_count"] == 0


def test_command_cannot_overwrite_an_input_file(tmp_path, raw_event, capsys):
    from cloud_ir_lab.cli import main

    path = tmp_path / "findings.json"
    original = json.dumps({"Records": [raw_event]})
    path.write_text(original, encoding="utf-8")
    assert main(["analyze", str(path), "--output-dir", str(tmp_path)]) == 1
    assert "input" in capsys.readouterr().err.lower()
    assert path.read_text(encoding="utf-8") == original


def test_markdown_keeps_markup_in_log_fields_inert(tmp_path, raw_event):
    from cloud_ir_lab.cli import main

    raw_event["sourceIPAddress"] = "203.0.113.77"
    raw_event["userIdentity"]["arn"] = "<img src='https://example.invalid/'>"
    raw_event["eventName"] = "LabExample"
    path = tmp_path / "event.json"
    path.write_text(json.dumps({"Records": [raw_event]}), encoding="utf-8")
    assert main(["analyze", str(path), "--output-dir", str(tmp_path / "reports")]) == 0
    markdown = (tmp_path / "reports" / "incident-report.md").read_text(encoding="utf-8")
    assert "&lt;img" in markdown
    assert '    "arn": "<img' in markdown
