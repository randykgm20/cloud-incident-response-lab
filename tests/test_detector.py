from copy import deepcopy
from ipaddress import ip_address

import pytest


@pytest.mark.parametrize(
    ("fixture", "rule_id", "severity", "resource", "technique"),
    [
        ("failed_logins", "repeated-auth-failure", "medium", "arn:aws:iam::000000000000:user/lab-learner", "T1110.001"),
        ("overly_permissive_policy", "overly-permissive-policy", "high", "LabOverbroadPolicy", None),
        ("privilege_escalation", "self-assigned-admin", "high", "arn:aws:iam::000000000000:user/lab-operator", "T1098.003"),
        ("logging_disabled", "cloudtrail-disabled", "high", "lab-demo-trail", "T1562.008"),
        ("public_bucket", "public-bucket-permissions", "high", "lab-demo-records", None),
        ("unusual_source", "unusual-source", "low", None, None),
    ],
)
def test_synthetic_scenario(synthetic_dir, fixture, rule_id, severity, resource, technique):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events

    events = load_events(synthetic_dir / f"{fixture}.json")
    finding, = analyze(events)
    assert finding.rule_id == rule_id
    assert finding.severity == severity
    assert finding.resource == resource
    assert (finding.attack.technique_id if finding.attack else None) == technique
    assert finding.evidence == tuple(event.raw for event in events)
    assert finding.timestamp == events[-1].timestamp
    assert finding.identity == events[-1].identity
    assert finding.source_ip == events[-1].source_ip
    assert finding.name and finding.interpretation and finding.recommended_action


def test_normal_activity_does_not_alert(synthetic_dir):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events

    assert analyze(load_events(synthetic_dir / "normal_activity.json")) == []


@pytest.mark.parametrize(
    ("first_time", "different_user", "count", "expected"),
    [
        ("13:59:00", False, 3, 1),
        ("13:58:59", False, 3, 0),
        ("14:02:00", True, 3, 0),
        ("14:02:00", False, 2, 0),
    ],
)
def test_login_threshold_is_per_identity_within_ten_minutes(
    synthetic_dir, first_time, different_user, count, expected
):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events, parse_event

    first, second, third = load_events(synthetic_dir / "failed_logins.json")
    altered = deepcopy(first.raw)
    altered["eventTime"] = f"2026-01-15T{first_time}Z"
    if different_user:
        altered["userIdentity"]["arn"] = "arn:aws:iam::000000000000:user/lab-other"
        altered["userIdentity"]["userName"] = "lab-other"
    events = [parse_event(altered), second, third]
    assert len(analyze(events[:count])) == expected


@pytest.mark.parametrize(
    ("fixture", "rule_id"),
    [
        ("overly_permissive_policy", "overly-permissive-policy"),
        ("privilege_escalation", "self-assigned-admin"),
        ("logging_disabled", "cloudtrail-disabled"),
        ("public_bucket", "public-bucket-permissions"),
    ],
)
def test_rejected_change_does_not_claim_configuration_changed(synthetic_dir, fixture, rule_id):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events, parse_event

    event, = load_events(synthetic_dir / f"{fixture}.json")
    rejected = parse_event({**event.raw, "errorCode": "AccessDenied"})
    assert all(finding.rule_id != rule_id for finding in analyze([rejected]))


def test_ip_baseline_can_be_replaced(synthetic_dir):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events

    events = load_events(synthetic_dir / "unusual_source.json")
    assert analyze(events, known_sources={ip_address("203.0.113.77")}) == []


def test_service_hostname_is_not_treated_as_unusual_ip(raw_event):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import parse_event

    event = parse_event({**raw_event, "sourceIPAddress": "cloudtrail.amazonaws.com"})
    assert analyze([event]) == []


def test_assigning_another_user_does_not_match_self_assignment(synthetic_dir):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events, parse_event

    event, = load_events(synthetic_dir / "privilege_escalation.json")
    request = {**event.request, "userName": "lab-other"}
    assert analyze([parse_event({**event.raw, "requestParameters": request})]) == []


@pytest.mark.parametrize("effect,condition", [("Deny", {}), ("Allow", {"Bool": {"aws:SecureTransport": "true"}})])
def test_wildcard_policy_requires_unconditional_allow(synthetic_dir, effect, condition):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events, parse_event

    event, = load_events(synthetic_dir / "overly_permissive_policy.json")
    policy = {"Statement": {"Effect": effect, "Action": ["*"], "Resource": ["*"]}}
    if condition:
        policy["Statement"]["Condition"] = condition
    request = {**event.request, "policyDocument": policy}
    assert analyze([parse_event({**event.raw, "requestParameters": request})]) == []


@pytest.mark.parametrize("grant, expected", [("*", 1), ("arn:aws:iam::000000000000:root", 0)])
def test_public_bucket_policy_requires_public_principal(synthetic_dir, grant, expected):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events, parse_event

    event, = load_events(synthetic_dir / "public_bucket.json")
    request = {
        "bucketName": "lab-demo-records",
        "bucketPolicy": {
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": grant},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::lab-demo-records/*",
            }
        },
    }
    changed = {**event.raw, "eventName": "PutBucketPolicy", "requestParameters": request}
    assert len(analyze([parse_event(changed)])) == expected


def test_deleting_trail_matches_logging_rule(synthetic_dir):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events, parse_event

    event, = load_events(synthetic_dir / "logging_disabled.json")
    findings = analyze([parse_event({**event.raw, "eventName": "DeleteTrail"})])
    assert [finding.rule_id for finding in findings] == ["cloudtrail-disabled"]


def test_four_failed_events_produce_one_finding(synthetic_dir):
    from cloud_ir_lab.detector import analyze
    from cloud_ir_lab.parser import load_events, parse_event

    events = load_events(synthetic_dir / "failed_logins.json")
    fourth = {**events[-1].raw, "eventID": "lab-extra", "eventTime": "2026-01-15T14:10:00Z"}
    finding, = analyze([*events, parse_event(fourth)])
    assert len(finding.evidence) == 3
