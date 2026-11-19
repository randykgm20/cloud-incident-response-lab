import json
from datetime import datetime, timezone
from math import isfinite
from pathlib import Path
from typing import Any

from .models import Event, JsonObject


class InputError(ValueError):
    """Input files could not be read or do not meet the lab's event format."""


def _required_text(record: JsonObject, field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{field} must be a nonempty string")
    return value


def _optional_object(record: JsonObject, field: str) -> JsonObject:
    value = record.get(field)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise InputError(f"{field} must be an object or null")
    return value


def parse_event(record: object) -> Event:
    """Build a validated event while retaining the original JSON fields."""
    if not isinstance(record, dict):
        raise InputError("event must be an object")

    raw_time = _required_text(record, "eventTime")
    try:
        timestamp = datetime.fromisoformat(raw_time)
        if timestamp.tzinfo is None:
            raise ValueError("missing time offset")
        timestamp = timestamp.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise InputError("eventTime must be a date and time with a UTC offset") from exc

    user = _optional_object(record, "userIdentity")
    identity = next(
        (
            user[key]
            for key in ("arn", "principalId", "userName")
            if isinstance(user.get(key), str) and user[key].strip()
        ),
        None,
    )
    if identity is None:
        raise InputError("userIdentity must provide an arn, principalId, or userName")

    error_code = record.get("errorCode")
    if error_code is not None:
        error_code = _required_text(record, "errorCode")

    return Event(
        event_id=_required_text(record, "eventID"),
        timestamp=timestamp,
        service=_required_text(record, "eventSource"),
        name=_required_text(record, "eventName"),
        identity=identity,
        source_ip=_required_text(record, "sourceIPAddress"),
        request=_optional_object(record, "requestParameters"),
        response=_optional_object(record, "responseElements"),
        error_code=error_code,
        raw=record,
    )


def _invalid_constant(value: str) -> None:
    raise ValueError(f"{value} is not a JSON number")


def _finite_float(value: str) -> float:
    number = float(value)
    if not isfinite(number):
        raise ValueError("number is outside the supported range")
    return number


def _unique_object(pairs: list[tuple[str, Any]]) -> JsonObject:
    record: JsonObject = {}
    for key, value in pairs:
        if key in record:
            raise ValueError(f"duplicate field {key!r}")
        record[key] = value
    return record


def read_json(path: Path) -> Any:
    try:
        content = path.read_text(encoding="utf-8-sig")
        return json.loads(
            content,
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
            parse_float=_finite_float,
        )
    except (OSError, ValueError, RecursionError) as exc:
        raise InputError(f"{path}: could not read JSON ({exc})") from exc

def _read_records(path: Path) -> list[object]:
    payload = read_json(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("Records"), list):
        raise InputError(f"{path}: expected an object with a Records array")
    return payload["Records"]


def load_events(source: Path) -> list[Event]:
    """Read one log or a flat folder of logs, deduplicate, and sort by time."""
    try:
        if source.is_dir():
            paths = sorted(
                path for path in source.iterdir()
                if path.suffix.lower() == ".json" and path.is_file()
            )
        else:
            paths = [source]
    except OSError as exc:
        raise InputError(f"{source}: could not list input files ({exc})") from exc
    if not paths:
        raise InputError(f"{source}: no JSON files found")

    events: dict[str, Event] = {}
    locations: dict[str, str] = {}
    for path in paths:
        for index, record in enumerate(_read_records(path)):
            location = f"{path} Records[{index}]"
            try:
                event = parse_event(record)
            except InputError as exc:
                raise InputError(f"{location}: {exc}") from exc

            previous = events.get(event.event_id)
            if previous is None:
                events[event.event_id] = event
                locations[event.event_id] = location
            elif json.dumps(previous.raw, sort_keys=True) != json.dumps(event.raw, sort_keys=True):
                first = locations[event.event_id]
                raise InputError(
                    f"{location}: conflicting records for eventID {event.event_id!r}; "
                    f"first seen at {first}"
                )

    return sorted(events.values(), key=lambda event: (event.timestamp, event.event_id))
