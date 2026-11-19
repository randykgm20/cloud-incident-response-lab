import json
from datetime import datetime, timezone

import pytest


def test_loads_cloudtrail_record_and_preserves_evidence(synthetic_dir, raw_event):
    from cloud_ir_lab.parser import load_events

    first, *_ = load_events(synthetic_dir / "normal_activity.json")
    assert first.event_id == raw_event["eventID"]
    assert first.identity == "arn:aws:iam::000000000000:user/lab-operator"
    assert first.timestamp == datetime(2026, 1, 15, 13, 59, tzinfo=timezone.utc)
    assert first.raw == raw_event


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("eventID", None),
        ("eventTime", "tomorrow"),
        ("eventTime", "2026-01-15T13:59:00"),
        ("eventSource", 3),
        ("eventName", ""),
        ("sourceIPAddress", []),
        ("userIdentity", {}),
        ("requestParameters", False),
        ("responseElements", []),
        ("errorCode", 1),
    ],
)
def test_reports_invalid_field_with_record_location(tmp_path, raw_event, field, invalid):
    from cloud_ir_lab.parser import InputError, load_events

    path = tmp_path / "bad.json"
    raw_event[field] = invalid
    path.write_text(json.dumps({"Records": [raw_event]}), encoding="utf-8")
    with pytest.raises(InputError, match=rf"bad\.json.*Records\[0\].*{field}"):
        load_events(path)


def test_rejects_missing_required_field(raw_event):
    from cloud_ir_lab.parser import InputError, parse_event

    del raw_event["eventName"]
    with pytest.raises(InputError, match="eventName"):
        parse_event(raw_event)


@pytest.mark.parametrize("body", ["[", "{}", '{"Records": {}}', '{"Records": [42]}', '{"Records": [NaN]}'])
def test_rejects_malformed_log_file(tmp_path, body):
    from cloud_ir_lab.parser import InputError, load_events

    path = tmp_path / "bad.json"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(InputError, match=r"bad\.json"):
        load_events(path)


def test_empty_directory_reports_missing_input(tmp_path):
    from cloud_ir_lab.parser import InputError, load_events

    with pytest.raises(InputError, match="no JSON files"):
        load_events(tmp_path)


def test_rejects_duplicate_json_field_before_evidence_is_lost(tmp_path, raw_event):
    from cloud_ir_lab.parser import InputError, load_events

    event_text = json.dumps(raw_event)
    duplicate = event_text[:-1] + ', "sourceIPAddress": "203.0.113.9"}'
    path = tmp_path / "duplicate-field.json"
    path.write_text('{"Records": [' + duplicate + ']}', encoding="utf-8")
    with pytest.raises(InputError, match=r"duplicate-field\.json.*duplicate field.*sourceIPAddress"):
        load_events(path)


def test_loads_records_in_time_order(synthetic_dir):
    from cloud_ir_lab.parser import load_events

    events = load_events(synthetic_dir / "failed_logins.json")
    assert [event.timestamp.minute for event in events] == [2, 5, 9]


def test_collapses_identical_duplicate_across_files(tmp_path, raw_event):
    from cloud_ir_lab.parser import load_events

    for name in ("a.json", "b.json"):
        (tmp_path / name).write_text(json.dumps({"Records": [raw_event]}), encoding="utf-8")
    assert len(load_events(tmp_path)) == 1


def test_rejects_conflicting_duplicate(tmp_path, raw_event):
    from cloud_ir_lab.parser import InputError, load_events

    copy = {**raw_event, "sourceIPAddress": "203.0.113.9"}
    path = tmp_path / "conflict.json"
    path.write_text(json.dumps({"Records": [raw_event, copy]}), encoding="utf-8")
    with pytest.raises(InputError, match="conflicting records"):
        load_events(path)


def test_duplicate_comparison_preserves_json_value_types(tmp_path, raw_event):
    from cloud_ir_lab.parser import InputError, load_events

    records = [{**raw_event, "readOnly": True}, {**raw_event, "readOnly": 1}]
    path = tmp_path / "conflicting-types.json"
    path.write_text(json.dumps({"Records": records}), encoding="utf-8")
    with pytest.raises(InputError, match="conflicting records"):
        load_events(path)
