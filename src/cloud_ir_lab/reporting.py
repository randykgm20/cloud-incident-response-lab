import json
import re
from collections import Counter
from dataclasses import asdict
from html import escape
from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory

from .models import Finding, JsonObject
from .tuning import SuppressedFinding

JSON_REPORT = "findings.json"
MARKDOWN_REPORT = "incident-report.md"


def _finding_record(finding: Finding) -> JsonObject:
    return {
        "rule_id": finding.rule_id,
        "name": finding.name,
        "severity": finding.severity,
        "interpretation": finding.interpretation,
        "identity": finding.identity,
        "timestamp": finding.timestamp.isoformat().replace("+00:00", "Z"),
        "source_ip": finding.source_ip,
        "resource": finding.resource,
        "evidence": list(finding.evidence),
        "recommended_action": finding.recommended_action,
        "attack": asdict(finding.attack) if finding.attack else None,
    }


def build_report(
    event_count: int,
    findings: list[Finding],
    *,
    suppressed: list[SuppressedFinding] | None = None,
) -> JsonObject:
    severity_counts = Counter(finding.severity for finding in findings)
    suppressed_records = []
    for item in suppressed or []:
        record = _finding_record(item.finding)
        record["suppression_reason"] = item.reason
        suppressed_records.append(record)
    return {
        "schema_version": 1,
        "event_count": event_count,
        "finding_count": len(findings),
        "severity_counts": {level: severity_counts[level] for level in ("high", "medium", "low")},
        "findings": [_finding_record(finding) for finding in findings],
        "suppressed_count": len(suppressed_records),
        "suppressed_findings": suppressed_records,
    }


def summary(report: JsonObject) -> str:
    counts = report["severity_counts"]
    return (
        f"{report['event_count']} events analyzed | {report['finding_count']} findings "
        f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low)"
        f" | {report.get('suppressed_count', 0)} suppressed"
    )


def _markdown_text(value: str) -> str:
    text = escape(" ".join(value.split()))
    return re.sub(r"([\\*_{}\[\]()#!|~`])", r"\\\1", text)


def _markdown(report: JsonObject) -> str:
    lines = [
        "# Synthetic cloud incident report",
        "",
        summary(report),
        "",
        "Findings are leads for analyst review. The evidence below comes from synthetic records.",
    ]
    if not report["findings"]:
        lines.extend(["", "No findings require active review. See any suppressed findings below."])
    for finding in [*report["findings"], *report.get("suppressed_findings", [])]:
        if "suppression_reason" in finding:
            lines.extend(["", "## Suppressed findings", "", _markdown_text(finding["suppression_reason"])])
        attack = finding["attack"]
        attack_label = (
            f"{attack['technique_id']} {attack['technique']} ({attack['tactic']})"
            if attack else "Unmapped"
        )
        resource = finding["resource"] or "Unknown"
        lines.extend([
            "",
            f"## {_markdown_text(finding['name'])}",
            "",
            f"- Rule **{_markdown_text(finding['rule_id'])}**",
            f"- Severity **{finding['severity']}**",
            f"- Identity {_markdown_text(finding['identity'])}",
            f"- Time {finding['timestamp']}",
            f"- Source {_markdown_text(finding['source_ip'])}",
            f"- Affected resource {_markdown_text(resource)}",
            f"- MITRE ATT&CK {_markdown_text(attack_label)}",
            "",
            "### Analyst interpretation",
            "",
            _markdown_text(finding["interpretation"]),
            "",
            "### Recommended analyst action",
            "",
            _markdown_text(finding["recommended_action"]),
            "",
            "### Observed evidence",
            "",
            "```json",
            json.dumps(finding["evidence"], indent=2, allow_nan=False),
            "```",
        ])
    return "\n".join(lines) + "\n"


def write_reports(report: JsonObject, output_dir: Path) -> tuple[Path, Path]:
    json_path = output_dir / JSON_REPORT
    markdown_path = output_dir / MARKDOWN_REPORT
    json_text = json.dumps(report, indent=2, allow_nan=False) + "\n"
    markdown_text = _markdown(report)
    output_dir.mkdir(parents=True, exist_ok=True)
    for destination in (json_path, markdown_path):
        if destination.is_symlink():
            raise OSError(f"{destination}: report destinations cannot be symbolic links")
        if destination.exists() and not destination.is_file():
            raise OSError(f"{destination}: expected a report file")

    # Prepare both reports and backups before publication. Roll back ordinary write failures.
    with TemporaryDirectory(prefix=".report-", dir=output_dir) as staging:
        staged_json = Path(staging) / JSON_REPORT
        staged_markdown = Path(staging) / MARKDOWN_REPORT
        staged_json.write_text(json_text, encoding="utf-8", newline="\n")
        staged_markdown.write_text(markdown_text, encoding="utf-8", newline="\n")
        destinations = (json_path, markdown_path)
        backups = {}
        for destination in destinations:
            backup = Path(staging) / ("previous-" + destination.name)
            if destination.exists():
                copyfile(destination, backup)
                backups[destination] = backup

        published = []
        try:
            for staged, destination in zip((staged_json, staged_markdown), destinations):
                staged.replace(destination)
                published.append(destination)
        except OSError as exc:
            try:
                for destination in reversed(published):
                    if destination in backups:
                        backups[destination].replace(destination)
                    else:
                        destination.unlink()
            except OSError as rollback_error:
                raise OSError(
                    f"report publication failed ({exc}); rollback failed ({rollback_error}); "
                    "inspect both report files before using them"
                ) from rollback_error
            raise
    return json_path, markdown_path
