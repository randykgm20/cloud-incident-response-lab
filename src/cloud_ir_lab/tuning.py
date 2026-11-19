"""Audited, exact-match approvals for expected synthetic activity."""
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path

from .models import Finding
from .parser import InputError, read_json


class ConfigError(ValueError):
    """The tuning configuration is malformed or unsupported."""


@dataclass(frozen=True)
class Approval:
    rule_id: str
    identity: str
    source_ip: str
    reason: str


@dataclass(frozen=True)
class SuppressedFinding:
    finding: Finding
    reason: str


def load_config(path: Path, rule_ids: set[str]) -> tuple[Approval, ...]:
    try:
        data = read_json(path)
        if not isinstance(data, dict) or set(data) != {"schema_version", "approvals"}:
            raise ConfigError("configuration fields must be schema_version and approvals")
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ConfigError("unsupported schema_version")
        if not isinstance(data["approvals"], list):
            raise ConfigError("approvals must be an array")
        approvals = []
        seen = set()
        for index, item in enumerate(data["approvals"]):
            label = f"approvals[{index}]"
            fields = {"rule_id", "identity", "source_ip", "reason"}
            if not isinstance(item, dict) or set(item) != fields:
                raise ConfigError(f"{label}: fields must be {sorted(fields)}")
            for field, value in item.items():
                if not isinstance(value, str) or not value.strip():
                    raise ConfigError(f"{label}.{field} must be a nonempty string")
            if item["rule_id"] not in rule_ids:
                raise ConfigError(f"{label}: unknown rule {item['rule_id']!r}")
            if "*" in item["identity"] or "?" in item["identity"]:
                raise ConfigError(f"{label}.identity must be an exact identity")
            try:
                address = str(ip_address(item["source_ip"]))
            except ValueError as exc:
                raise ConfigError(f"{label}.source_ip must be one IP address") from exc
            key = (item["rule_id"], item["identity"], address)
            if key in seen:
                raise ConfigError(f"{label}: duplicate approval")
            seen.add(key)
            approvals.append(Approval(*key, reason=item["reason"]))
        return tuple(approvals)
    except (InputError, ConfigError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc


def _matches(finding: Finding, approval: Approval) -> bool:
    if finding.rule_id != approval.rule_id or finding.identity != approval.identity:
        return False
    for record in finding.evidence:
        user = record["userIdentity"]
        identity = next(
            (user[key] for key in ("arn", "principalId", "userName")
             if isinstance(user.get(key), str) and user[key].strip()),
            None,
        )
        try:
            address = str(ip_address(record["sourceIPAddress"]))
        except ValueError:
            return False
        if identity != approval.identity or address != approval.source_ip:
            return False
    return bool(finding.evidence)


def apply_tuning(
    findings: list[Finding], approvals: tuple[Approval, ...]
) -> tuple[list[Finding], list[SuppressedFinding]]:
    active = []
    suppressed = []
    for finding in findings:
        match = next((approval for approval in approvals if _matches(finding, approval)), None)
        if match is None:
            active.append(finding)
        else:
            suppressed.append(SuppressedFinding(finding, match.reason))
    return active, suppressed
