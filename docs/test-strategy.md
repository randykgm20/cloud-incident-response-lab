# Test strategy

Test-driven development means first writing a test that shows missing or incorrect behavior, observing the failure, implementing the smallest correction, and rerunning the tests. A test is evidence about the cases it exercises.

The baseline suite passed before the final portfolio changes. New rule-loading, detection, tuning, and report-publication tests were run before their implementations. Report publication and Markdown escaping fixes were verified against the failures that exposed them.

## Test coverage by module

| File | Behavior protected |
| --- | --- |
| `test_parser.py` | Valid records, missing fields, malformed JSON and timestamps, repeated JSON keys, sorting, identical copies, and conflicting duplicates. |
| `test_rules.py` | Packaged rule loading, schema checks, duplicate identifiers, unsupported fields and conditions, changed thresholds, and evaluated selectors. |
| `test_detector.py` | The original six suspicious scenarios, normal activity, severity, evidence, window boundaries, rejected changes, and narrower policy behavior. |
| `test_new_detections.py` | Root and cross-user key matches, harmless cases, malformed optional fields, missing names, username boundaries, service/operation checks, and malformed timestamps. |
| `test_tuning.py` | Exact suppression, retained evidence and reasons, unrelated alerts, mixed-source correlation, invalid configs, and command errors. |
| `test_reporting.py` | Command behavior, JSON and Markdown structure, normal results, filesystem errors, input-file protection, and evidence rendering. |
| `test_evidence_handling.py` | Preparation and publication failures, rollback to existing or absent outputs, escaped rule metadata, deterministic order, symbolic-link rejection, and new fixture controls. |

Tests use actual parsers, rules, detections, and files. Failure tests replace a single filesystem method to inject a controlled error while checking the real output files. This use of a test double allows a repeatable failure that would otherwise depend on operating-system permissions or timing.

## Run the suite

The following command runs every test using the project's environment. The temporary folder is disposable and stays inside the repository.

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp .pytest-tmp
```

A specific file can be placed after `pytest` to focus investigation. Always rerun the full suite after a meaningful change. Record a test count only after reading the final result.

## Installation and manual verification

An independent local virtual environment is used to test an ordinary package wheel. The wheel is inspected for all rule files, installed offline, and run outside the source directory. This catches a packaging mistake that an editable source install could hide.

The final verification also runs the complete sample, both normal controls, the tuning comparison, the custom-rule command, and the hunting case. It compares JSON and Markdown findings, original evidence, duplicate handling, and deterministic output. Generated reports and fixture files are reviewed for sensitive content. These checks complement automated tests and are recorded in the résumé evidence after execution.
