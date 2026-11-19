from copy import deepcopy

import pytest


def root_record(raw_event):
    record = deepcopy(raw_event)
    record["userIdentity"] = {"type": "Root", "arn": "arn:aws:iam::000000000000:root"}
    return record


def key_record(raw_event):
    record = deepcopy(raw_event)
    record.update(eventSource="iam.amazonaws.com", eventName="CreateAccessKey")
    record["requestParameters"] = {"userName": "lab-service"}
    return record


def test_root_activity_includes_denied_attempts(raw_event):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import parse_event

    record = root_record(raw_event)
    record["errorCode"] = "AccessDenied"
    finding, = analyze([parse_event(record)])
    assert finding.rule_id == "root-account-activity"
    assert finding.severity == "high"
    assert finding.attack is None
    assert finding.evidence == (record,)


@pytest.mark.parametrize("identity_type", ["IAMUser", "AssumedRole", None, [], "root"])
def test_root_rule_requires_exact_recorded_root_type(raw_event, identity_type):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import parse_event

    record = root_record(raw_event)
    record["userIdentity"]["type"] = identity_type
    assert analyze([parse_event(record)]) == []


def test_key_creation_for_another_user_preserves_target_and_evidence(raw_event):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import parse_event

    record = key_record(raw_event)
    finding, = analyze([parse_event(record)])
    assert finding.rule_id == "access-key-for-other-user"
    assert finding.resource == "lab-service"
    assert finding.attack.technique_id == "T1098.001"
    assert finding.evidence == (record,)


@pytest.mark.parametrize("target", [None, "", " ", [], {}, 4, "LAB-OPERATOR", "x" * 65, "bad name"])
def test_cross_user_key_rule_requires_a_different_valid_username(raw_event, target):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import parse_event

    record = key_record(raw_event)
    record["requestParameters"]["userName"] = target
    assert analyze([parse_event(record)]) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [("errorCode", "AccessDenied"), ("eventSource", "s3.amazonaws.com"), ("eventName", "ListAccessKeys")],
)
def test_key_rule_checks_outcome_service_and_operation(raw_event, field, value):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import parse_event

    record = key_record(raw_event)
    record[field] = value
    assert analyze([parse_event(record)]) == []


@pytest.mark.parametrize("actor", [None, [], "bad name"])
def test_key_rule_avoids_guessing_an_unknown_actor_name(raw_event, actor):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import parse_event

    record = key_record(raw_event)
    record["userIdentity"]["userName"] = actor
    assert analyze([parse_event(record)]) == []


def test_key_target_maximum_username_length_is_supported(raw_event):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import parse_event

    record = key_record(raw_event)
    record["requestParameters"]["userName"] = "x" * 64
    finding, = analyze([parse_event(record)])
    assert finding.resource == "x" * 64


@pytest.mark.parametrize("factory", [root_record, key_record])
def test_new_scenarios_still_require_valid_timestamp(raw_event, factory):
    from cloud_ir_lab.parser import InputError, parse_event

    record = factory(raw_event)
    record["eventTime"] = "2026-01-15T25:00:00Z"
    with pytest.raises(InputError, match="eventTime"):
        parse_event(record)
