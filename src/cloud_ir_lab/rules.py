"""Validate the lab's documented Sigma-style JSON rule subset."""
import re
from dataclasses import dataclass
from pathlib import Path

from .models import AttackMapping, JsonObject, Severity
from .parser import InputError, read_json

DEFAULT_RULE_DIR = Path(__file__).with_name("rule_data")
CONDITIONS = {
    "repeated_console_failures", "unconditional_wildcard_policy", "self_assigned_admin",
    "logging_disabled", "public_bucket_permissions", "unusual_source",
    "root_activity", "cross_user_access_key",
}
SELECTORS = {"eventSource", "eventName", "userIdentity.type", "responseElements.ConsoleLogin"}
FIELDS = {
    "id", "title", "description", "status", "logsource", "detection", "level",
    "attack", "falsepositives", "recommended_action", "notes",
}


class RuleError(ValueError):
    """A rule document is malformed or unsupported."""


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    interpretation: str
    action: str
    attack: AttackMapping | None
    selection: JsonObject
    condition: str
    parameters: dict[str, int]
    status: str
    falsepositives: tuple[str, ...]
    notes: tuple[str, ...]


def _fields(value: object, expected: set[str], label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise RuleError(f"{label} must be an object")
    unsupported = set(value) - expected
    missing = expected - set(value)
    if unsupported or missing:
        raise RuleError(f"{label}: unsupported fields {sorted(unsupported)}; missing fields {sorted(missing)}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuleError(f"{label} must be a nonempty string")
    return value


def _texts(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise RuleError(f"{label} must be a nonempty string array")
    return tuple(_text(item, label) for item in value)


def _parse_rule(document: object) -> Rule:
    data = _fields(document, FIELDS, "rule")
    identifier = _text(data["id"], "id")
    if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identifier) is None:
        raise RuleError("id must contain lowercase words separated by hyphens")
    if data["logsource"] != {"product": "aws", "service": "cloudtrail"}:
        raise RuleError("logsource must specify product aws and service cloudtrail")
    status = _text(data["status"], "status")
    if status not in {"experimental", "test", "stable"}:
        raise RuleError("unsupported status")
    level = _text(data["level"], "level")
    if level not in {"low", "medium", "high"}:
        raise RuleError("level must be low, medium, or high")

    detection = _fields(data["detection"], {"selection", "condition", "parameters"}, "detection")
    selection = detection["selection"]
    if not isinstance(selection, dict) or set(selection) - SELECTORS:
        raise RuleError("selection has unsupported fields or must be an object")
    for field, value in selection.items():
        if isinstance(value, list):
            _texts(value, f"selection.{field}")
        else:
            _text(value, f"selection.{field}")
    condition = _text(detection["condition"], "condition")
    if condition not in CONDITIONS:
        raise RuleError(f"unsupported condition {condition!r}")
    parameter_names = {"threshold", "window_minutes"} if condition == "repeated_console_failures" else set()
    parameters = _fields(detection["parameters"], parameter_names, "parameters")
    for name, number in parameters.items():
        upper_bound = 1000 if name == "threshold" else 1440
        lower_bound = 2 if name == "threshold" else 1
        if type(number) is not int or not lower_bound <= number <= upper_bound:
            raise RuleError(f"{name} must be an integer from {lower_bound} to {upper_bound}")

    attack = None
    if data["attack"] is not None:
        mapping = _fields(data["attack"], {"technique_id", "technique", "tactic"}, "attack")
        technique_id = _text(mapping["technique_id"], "attack.technique_id")
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id) is None:
            raise RuleError("attack.technique_id must be a technique identifier")
        attack = AttackMapping(
            technique_id, _text(mapping["technique"], "attack.technique"),
            _text(mapping["tactic"], "attack.tactic"),
        )
    return Rule(
        identifier, _text(data["title"], "title"), level,
        _text(data["description"], "description"), _text(data["recommended_action"], "recommended_action"),
        attack, selection, condition, parameters, status,
        _texts(data["falsepositives"], "falsepositives"), _texts(data["notes"], "notes"),
    )


def load_rules(directory: Path | None = None) -> list[Rule]:
    folder = directory if directory is not None else DEFAULT_RULE_DIR
    try:
        if not folder.is_dir():
            raise RuleError(f"{folder}: expected a rule directory")
        paths = sorted(folder.glob("*.json"))
        if not paths:
            raise RuleError(f"{folder}: no rule files")
        rules = []
        identifiers: set[str] = set()
        for path in paths:
            try:
                rule = _parse_rule(read_json(path))
                if rule.id in identifiers:
                    raise RuleError(f"duplicate rule identifier {rule.id!r}")
            except (RuleError, InputError) as exc:
                raise RuleError(f"{path}: {exc}") from exc
            identifiers.add(rule.id)
            rules.append(rule)
    except OSError as exc:
        raise RuleError(f"{folder}: could not read rules ({exc})") from exc
    return sorted(rules, key=lambda rule: rule.id)
