import argparse
import sys
from ipaddress import ip_address
from pathlib import Path

from .detector import DEFAULT_KNOWN_SOURCES, analyze
from .parser import InputError, load_events
from .reporting import JSON_REPORT, MARKDOWN_REPORT, build_report, summary, write_reports
from .rules import DEFAULT_RULE_DIR, RuleError, load_rules
from .tuning import ConfigError, apply_tuning, load_config


def _check_output_location(
    source: Path, output_dir: Path, config: Path | None, rules_dir: Path | None
) -> None:
    input_path = source.resolve()
    if source.is_dir() and input_path == output_dir.resolve():
        raise InputError("the report folder must differ from the input folder")
    protected = {input_path}
    if config is not None:
        protected.add(config.resolve())
    rule_folder = rules_dir if rules_dir is not None else DEFAULT_RULE_DIR
    protected.update(path.resolve() for path in rule_folder.glob("*.json"))
    if any((output_dir / name).resolve() in protected for name in (JSON_REPORT, MARKDOWN_REPORT)):
        raise InputError("a report would overwrite an input log, rule, or configuration file")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze local, synthetic CloudTrail-style logs.")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("analyze", help="Analyze one JSON log or a folder of JSON logs.")
    command.add_argument("source", type=Path, help="A synthetic JSON file or folder.")
    command.add_argument(
        "--output-dir", type=Path, default=Path("reports"), help="Report folder (default: reports)."
    )
    command.add_argument(
        "--known-source", action="append", type=ip_address,
        help="Replace the built-in IP baseline. Repeat for each expected address.",
    )
    command.add_argument("--rules-dir", type=Path, help="Use a folder of validated Sigma-style JSON rules.")
    command.add_argument("--config", type=Path, help="Local exact-match activity approvals.")
    args = parser.parse_args(argv)

    try:
        _check_output_location(args.source, args.output_dir, args.config, args.rules_dir)
        rules = load_rules(args.rules_dir)
        approvals = load_config(args.config, {rule.id for rule in rules}) if args.config else ()
        events = load_events(args.source)
    except (InputError, RuleError, ConfigError, OSError, RuntimeError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 1

    known_sources = set(args.known_source) if args.known_source else DEFAULT_KNOWN_SOURCES
    active, suppressed = apply_tuning(analyze(events, known_sources, rules=rules), approvals)
    report = build_report(len(events), active, suppressed=suppressed)
    report["analysis_context"] = {
        "known_sources": sorted(str(address) for address in known_sources),
        "rule_ids": [rule.id for rule in rules],
        "tuning_config_used": args.config is not None,
    }
    try:
        json_path, markdown_path = write_reports(report, args.output_dir)
    except (OSError, ValueError) as exc:
        print(f"Could not save reports: {exc}", file=sys.stderr)
        return 1

    print(summary(report))
    for finding in report["findings"]:
        print(f"- [{finding['severity'].upper()}] {finding['name']}")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
