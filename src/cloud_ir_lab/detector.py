import json
import re
from collections import defaultdict, deque
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address

from .models import Event, Finding, JsonObject
from .rules import Rule, load_rules

IPAddress = IPv4Address | IPv6Address
DEFAULT_KNOWN_SOURCES = frozenset(map(ip_address, ("192.0.2.10", "198.51.100.23")))
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
PUBLIC_READ_ACTIONS = {"*", "s3:*", "s3:getobject", "s3:listbucket"}


def _nonempty_text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _strings(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()


def _unconditional_allows(document: object) -> list[JsonObject]:
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except (ValueError, RecursionError):
            return []
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    return [
        statement for statement in statements
        if isinstance(statement, dict)
        and statement.get("Effect") == "Allow"
        and "Condition" not in statement
    ]


def _is_broad_policy(event: Event) -> bool:
    return any(
        "*" in _strings(statement.get("Action"))
        and "*" in _strings(statement.get("Resource"))
        for statement in _unconditional_allows(event.request.get("policyDocument"))
    )


def _is_self_admin(event: Event) -> bool:
    user = event.raw["userIdentity"]
    actor = _nonempty_text(user.get("userName"))
    target = _nonempty_text(event.request.get("userName"))
    return (
        user.get("type") == "IAMUser"
        and actor is not None
        and target is not None
        and actor.casefold() == target.casefold()
        and event.request.get("policyArn") == ADMIN_POLICY
    )


def _is_public_bucket(event: Event) -> bool:
    if event.name == "PutBucketAcl":
        acl = _nonempty_text(event.request.get("x-amz-acl") or event.request.get("acl"))
        return acl in PUBLIC_ACLS
    for statement in _unconditional_allows(event.request.get("bucketPolicy")):
        principal = statement.get("Principal")
        aws_principal = principal.get("AWS") if isinstance(principal, dict) else principal
        actions = {action.lower() for action in _strings(statement.get("Action"))}
        if "*" in _strings(aws_principal) and actions & PUBLIC_READ_ACTIONS:
            return True
    return False


def _matches_selection(event: Event, rule: Rule) -> bool:
    for dotted_name, expected in rule.selection.items():
        value: object = event.raw
        for part in dotted_name.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value not in (expected if isinstance(expected, list) else [expected]):
            return False
    return True


def _finding(rule: Rule, event: Event, resource: str | None, evidence: tuple[Event, ...]) -> Finding:
    return Finding(
        rule_id=rule.id, name=rule.name, severity=rule.severity,
        interpretation=rule.interpretation, identity=event.identity,
        timestamp=event.timestamp, source_ip=event.source_ip,
        resource=resource, evidence=tuple(item.raw for item in evidence),
        recommended_action=rule.action, attack=rule.attack,
    )


def _configuration_finding(event: Event, rule: Rule) -> Finding | None:
    if rule.condition == "root_activity":
        return _finding(rule, event, event.identity, (event,))
    if event.error_code is not None:
        return None
    condition = rule.condition
    if condition == "unconditional_wildcard_policy" and _is_broad_policy(event):
        return _finding(rule, event, _nonempty_text(event.request.get("policyName")), (event,))
    if condition == "self_assigned_admin" and _is_self_admin(event):
        return _finding(rule, event, event.identity, (event,))
    if condition == "logging_disabled":
        return _finding(rule, event, _nonempty_text(event.request.get("name")), (event,))
    if condition == "public_bucket_permissions" and _is_public_bucket(event):
        return _finding(rule, event, _nonempty_text(event.request.get("bucketName")), (event,))
    if condition == "cross_user_access_key":
        actor = event.raw["userIdentity"].get("userName")
        target = event.request.get("userName")
        if _valid_username(actor) and _valid_username(target) and actor.casefold() != target.casefold():
            return _finding(rule, event, target, (event,))
    return None


def _valid_username(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,64}", value) is not None


def _is_unfamiliar_ip(source: str, known_sources: set[IPAddress] | frozenset[IPAddress]) -> bool:
    try:
        return ip_address(source) not in known_sources
    except ValueError:
        return False


def _event_resource(event: Event) -> str | None:
    resources = event.raw.get("resources")
    if isinstance(resources, list):
        for resource in resources:
            if isinstance(resource, dict) and (arn := _nonempty_text(resource.get("ARN"))):
                return arn
    return _nonempty_text(event.request.get("bucketName"))


def _correlate_failures(events: list[Event], rule: Rule) -> list[Finding]:
    findings = []
    failed_logins: dict[str, deque[Event]] = defaultdict(deque)
    reported: set[str] = set()
    window = timedelta(minutes=rule.parameters["window_minutes"])
    for event in events:
        if not _matches_selection(event, rule) or event.identity in reported:
            continue
        recent = failed_logins[event.identity]
        while recent and event.timestamp - recent[0].timestamp > window:
            recent.popleft()
        recent.append(event)
        if len(recent) == rule.parameters["threshold"]:
            findings.append(_finding(rule, event, event.identity, tuple(recent)))
            reported.add(event.identity)
            del failed_logins[event.identity]
    return findings


def analyze(
    events: list[Event],
    known_sources: set[IPAddress] | frozenset[IPAddress] = DEFAULT_KNOWN_SOURCES,
    *,
    rules: list[Rule] | None = None,
) -> list[Finding]:
    """Evaluate validated events with the lab's supported condition implementations."""
    ordered_events = sorted(events, key=lambda event: (event.timestamp, event.event_id))
    loaded_rules = load_rules() if rules is None else rules
    findings = []
    for rule in sorted(loaded_rules, key=lambda rule: rule.id):
        if rule.condition == "repeated_console_failures":
            findings.extend(_correlate_failures(ordered_events, rule))
            continue
        for event in ordered_events:
            if not _matches_selection(event, rule):
                continue
            if rule.condition == "unusual_source":
                if _is_unfamiliar_ip(event.source_ip, known_sources):
                    findings.append(_finding(rule, event, _event_resource(event), (event,)))
            elif finding := _configuration_finding(event, rule):
                findings.append(finding)
    return sorted(
        findings,
        key=lambda finding: (finding.timestamp, finding.evidence[-1]["eventID"], finding.rule_id),
    )
