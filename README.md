# Automated Cloud Incident Detection and Response Lab

A finished educational Python project for local analysis of synthetic Amazon Web Services (AWS) CloudTrail-style logs. CloudTrail records account activity such as sign-ins and permission changes. This lab validates those records, evaluates eight detection rules, and gives an analyst evidence and investigation leads.

The project demonstrates Python programming, Identity and Access Management (IAM), detection engineering, detection-as-code, false-positive tuning, and basic incident investigation. Detection engineering means designing and testing ways to recognize security-relevant patterns. Detection-as-code stores reviewable rules beside their tests and documentation.

## Demo at a glance

On the same three synthetic events, tuning changed **4 active findings** into **2 active findings and 2 documented suppressions**. The stopped-logging finding and another user's unfamiliar-source finding stayed active. Suppressed findings retain their original evidence and approval reason.

This helps an analyst reduce noise from approved activity while keeping other suspicious activity visible. Run the [tuning comparison commands](docs/tuning-guide.md#run-the-controlled-comparison) to reproduce the demonstration.

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

Install Python **3.11 or newer**. After cloning the repository, open Windows PowerShell in its root folder, which contains `pyproject.toml`. Check that the version printed by the first command is at least 3.11 before continuing.

The `py` command selects Python on Windows. `-m venv .venv` creates an isolated environment for this project. The remaining commands use that environment's interpreter directly, install the local package, and check its installed dependencies. `pip` is Python's package installer, and `-e` makes source edits available on the next run.

```powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip check
```

Running the lab uses Python's standard library. Package installation uses `setuptools>=64` as a build dependency. Automated tests additionally require the optional `test` extra declared in `pyproject.toml`, which installs `pytest>=8,<10` and its dependencies. Install that extra before running the tests.

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
```

Expect `No broken requirements found` from `pip check`. The standard installation can download dependencies from the configured package index. On macOS/Linux, use `python3 --version` and `python3 -m venv .venv`, confirming Python 3.11 or newer. Use `.venv/bin/python` for all later commands, including `.venv/bin/python -m pip install -e ".[test]"` for tests.

### Optional offline installation

Wheel files are packaged Python dependencies. Supply approved, compatible wheels separately in `.wheelhouse/` at the repository root. **Wheel files and virtual environments are excluded from a Git clone.** The offline wheel set needs `setuptools>=64` for installation. Testing also needs `pytest>=8,<10` and its dependencies, including any required by your Python version and operating system.

Create the environment with the first two setup commands above, then run the offline commands below. `PIP_NO_INDEX` disables package-index access for this PowerShell session and build subprocesses. `--find-links` points the installer at the local wheel folder.

```powershell
$env:PIP_NO_INDEX = "1"
$LabWheels = (Resolve-Path .wheelhouse).Path
.\.venv\Scripts\python.exe -m pip install --no-index --find-links $LabWheels -e .
.\.venv\Scripts\python.exe -m pip check
```

For offline testing, install the test extra from the same wheel folder.

```powershell
.\.venv\Scripts\python.exe -m pip install --no-index --find-links $LabWheels -e ".[test]"
```

On macOS/Linux, set `export PIP_NO_INDEX=1`, use `.venv/bin/python`, and pass the absolute wheel-folder path to `--find-links`.

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

After installing the `test` extra from the installation section, the next command runs every automated test. `-q` gives a short summary. `--basetemp` keeps disposable test files inside `.pytest-tmp` and clears that folder between runs.

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

Use the existing [handoff checklist](docs/portfolio-guide.md#git-review-and-commit-checklist) to review changes before staging or committing. License terms are in [LICENSE](LICENSE).
