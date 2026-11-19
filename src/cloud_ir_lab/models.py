from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

JsonObject = dict[str, Any]
Severity = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: datetime
    service: str
    name: str
    identity: str
    source_ip: str
    request: JsonObject
    response: JsonObject
    error_code: str | None
    raw: JsonObject


@dataclass(frozen=True)
class AttackMapping:
    technique_id: str
    technique: str
    tactic: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    name: str
    severity: Severity
    interpretation: str
    identity: str
    timestamp: datetime
    source_ip: str
    resource: str | None
    evidence: tuple[JsonObject, ...]
    recommended_action: str
    attack: AttackMapping | None
