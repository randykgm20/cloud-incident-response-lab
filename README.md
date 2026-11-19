# Automated Cloud Incident Detection and Response Lab

A finished educational Python project for local analysis of synthetic Amazon Web Services (AWS) CloudTrail-style logs. CloudTrail records account activity such as sign-ins and permission changes. This lab validates those records, evaluates eight detection rules, and gives an analyst evidence and investigation leads.

The project demonstrates Python programming, Identity and Access Management (IAM), detection engineering, detection-as-code, false-positive tuning, and basic incident investigation. Detection engineering means designing and testing ways to recognize security-relevant patterns. Detection-as-code stores reviewable rules beside their tests and documentation.

## Scope and safety

The supported workflow is local, in-memory batch analysis of fictional data. Live AWS monitoring, automatic incident containment, deployment, credential handling, and production security operations sit outside its capabilities. A production Security Information and Event Management (SIEM) or cloud-security platform provides collection, scale, access control, and operational safeguards beyond this lab. Keep inputs fictional and all reports local. The application cannot establish whether an arbitrary file is synthetic.

Fixtures use the fictional account identifier `000000000000` and addresses reserved for documentation. A credential-creation event describes a fictional action and contains no usable credential. Review [limitations and safety](docs/limitations.md) before extending the project.

## Data flow

```text
Synthetic JSON → validate and deduplicate → ordered events
Rule files → validate → detection engine → findings
Local approvals → exact-match tuning → active and suppressed findings
Findings → terminal summary + JSON report + Markdown report
```

JavaScript Object Notation (JSON) uses named fields to represent data. Markdown is a text format with headings and lists. Both reports keep source evidence and distinguish it from analyst interpretation. Each suppression includes its reason.

## Installation

Python 3.11 or newer is required. Run commands from this repository's root folder, which contains `pyproject.toml`. The supplied local folder has a prepared `.venv` virtual environment, an isolated Python installation for this project. The following command checks its version.

```powershell
.\.venv\Scripts\python.exe --version
```

### Fresh offline setup

The Windows commands below use Codex's bundled Python when it is available. `Join-Path` builds a filesystem path and `&` runs the executable stored in a variable. `-m venv` creates the isolated environment. Use these creation commands for a fresh checkout. For another machine, set `$LabPython` to the path of an approved local Python 3.11+ executable.

```powershell
$LabPython = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
& $LabPython --version
& $LabPython -m venv .venv
```

An offline install needs approved local Python packages called wheels in `.wheelhouse/`. This delivered workspace contains cached wheels. A Git checkout excludes them. For an offline copy, transfer the approved wheel files separately. The verified set contains setuptools 81.0.0, pytest 9.0.3, colorama 0.4.6, iniconfig 2.3.1, packaging 26.3, pluggy 1.7.0, and pygments 2.21.0. The runtime uses only Python's standard library. pytest is the development test runner.

The next commands disable package-index access, resolve the wheel folder to an absolute path, and install the project with its test dependencies. `-e` makes source edits available on the next run. `[test]` selects the testing dependency group.

```powershell
$env:PIP_NO_INDEX = "1"
$LabWheels = (Resolve-Path .wheelhouse).Path
.\.venv\Scripts\python.exe -m pip install --no-index --find-links $LabWheels -e ".[test]"
.\.venv\Scripts\python.exe -m pip check
```

Expect a successful installation and `No broken requirements found`. On Linux or macOS, create the environment with an approved `python3.11 -m venv .venv`, set `PIP_NO_INDEX=1` in the shell, and use `.venv/bin/python`.

## Run the detector

A command-line interface (CLI) accepts typed instructions. `-m cloud_ir_lab.cli` runs this project's CLI. `analyze` selects analysis, and the next argument identifies one file or a flat folder. `--output-dir` selects the report folder. Existing reports with the same filenames in that folder are replaced after preparation, so use a fresh folder to retain earlier results.

```powershell
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/synthetic/ --output-dir reports/portfolio/all
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/synthetic/normal_activity.json --output-dir reports/portfolio/normal
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/synthetic/normal_new_activity.json --output-dir reports/portfolio/normal-new
```

Expected summaries are 15 events with eight active findings for the full folder, three events with zero findings for the original control, and two events with zero findings for the added control. The full folder includes six high, one medium, and one low finding.

Each run saves `findings.json` and `incident-report.md`. The JSON report retains the original schema version and finding fields. Added fields record suppressed findings, suppression counts, and analysis configuration. Exit status `0` means analysis and report writing completed. Status `1` indicates a data, configuration, or file error. Invalid command syntax returns `2`.

### Example event

```json
{
  "Records": [{
    "eventID": "lab-example-001",
    "eventTime": "2026-01-15T14:12:00Z",
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging",
    "userIdentity": {"userName": "lab-operator"},
    "sourceIPAddress": "192.0.2.10",
    "requestParameters": {"name": "lab-demo-trail"}
  }]
}
```

A finding for that event identifies `lab-demo-trail`, includes the original event under `evidence`, and asks the analyst to check authorization and logging coverage. The detector's interpretation is a hypothesis requiring investigation.

## Detection-as-code and tuning

Eight packaged JSON files in `src/cloud_ir_lab/rule_data/` hold titles, conditions, severity, mapping, false-positive notes, and recommended actions. These are Sigma-style rules with a limited documented schema. Full official Sigma parsing, conversion, and backend compatibility are outside the implementation. Read the [rule-writing guide](docs/rule-writing-guide.md).

The tuning example compares one dataset before and after approved activity is configured. Both commands analyze the same three events.

```powershell
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/tuning/approved_activity.json --output-dir reports/portfolio/tuning-before
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/tuning/approved_activity.json --config config/approved_activity.json --output-dir reports/portfolio/tuning-after
```

Expect four active findings before tuning and two active plus two suppressed findings after tuning. A stopped-logging finding and another user's unfamiliar address stay active. See the [tuning guide](docs/tuning-guide.md) for the explanation and evidence.

Use `--rules-dir` to supply a validated rule folder. The existing `--known-source ADDRESS` option replaces the baseline Internet Protocol (IP) address list and can be repeated. The default addresses are `192.0.2.10` and `198.51.100.23`. The JSON analysis context records the effective list. Per-finding suppression auditing belongs to `--config`. Changing the baseline changes which source events qualify initially.

## Tests and investigation

The next command runs every automated test. `-q` gives a short summary. `--basetemp` keeps disposable test files inside `.pytest-tmp` and clears that folder between runs.

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp .pytest-tmp
```

Read the [test strategy](docs/test-strategy.md), then investigate the [threat-hunting exercise](docs/threat-hunting-exercise.md) before opening its answer key. Threat hunting is asking a security question and examining records to assess it.

## Portfolio guide

- [Architecture and data flow](docs/architecture.md)
- [Detection catalog](docs/detection-catalog.md)
- [Learning notes](docs/learning-notes.md)
- [Verified résumé evidence](docs/resume-evidence.md)
- [Demonstrations, elevator pitch, and interview answers](docs/portfolio-guide.md)
- [Final local implementation plan](docs/portfolio-plan.md)
- [Original Phase 1 plan](docs/project-plan.md)

The next useful improvements are deeper IAM policy semantics, measured rule tuning on expanded synthetic controls, and reproducible offline installation bundles. Live integration would require a separately authorized design and data-handling plan.

## Review and commit

Git tracks reviewed versions of files. `git status` lists changes, `git diff` shows working changes, and `git diff --check` checks whitespace. New files appear in status and can be read directly. Files already marked with intent-to-add also appear in diff. Use this review before staging.

```powershell
git status --short
git diff --check
git diff
```

After reviewing synthetic inputs, rule changes, tests, and ignore protections, stage only the intended files with `git add`. `git diff --cached` shows staged content before a commit. The current repository has no commits, so the first approved commit will capture the whole local project. See [the handoff checklist](docs/portfolio-guide.md#git-review-and-commit-checklist). License terms are in [LICENSE](LICENSE).
