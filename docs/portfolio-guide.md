# Portfolio and interview guide

## Thirty-second elevator pitch

“I built a local Python lab that analyzes synthetic cloud audit logs using eight readable rule files. I tested rule validation, detection boundaries, false-positive tuning, and report failures. Reports preserve original evidence and show which findings were suppressed and why. A fictional investigation exercise demonstrates how I build a timeline, distinguish facts from hypotheses, and identify missing evidence.”

## Two-minute interview explanation

“The problem I studied was how a cloud-security analyst turns individual activity records into investigation leads. I used fictional CloudTrail-style files and a normal control.

The parser validates required fields, preserves each record, rejects contradictory duplicate identifiers, collapses identical copies, and sorts by time. Ordering matters when correlating failed sign-ins.

I moved detection definitions into eight Sigma-style JSON files. Each has a selection, named condition, severity, false-positive considerations, and analyst action. The engine supports a limited documented schema and rejects unsupported fields, conditions, and duplicate identifiers.

The original rules cover repeated failures, wildcard policies, self-assigned administrator access, stopped logging, public bucket permissions, and unfamiliar addresses. I added root-account activity and an IAM user creating an access key for another named user.

For tuning, I required an exact rule, identity, and source address approval. The demo goes from four active findings to two active and two suppressed findings. Suppressed records retain their evidence and reason. The stopped-logging alert and another identity's source alert stay active.

My hunting exercise asks the student to inspect a successful sign-in after failures, a permission change, and a logging change. Its answer key separates recorded facts, interpretations, and assumptions.

Tests cover malformed input, rule boundaries, evidence, deterministic output, and recovery after report-write failures. I also verified an offline package installation. The scope is educational local batch analysis. Effective permissions, live monitoring, and operational response require further capabilities and authorization.”

## Five technical interview questions

**How does detection-as-code help?**

It stores rule intent and configuration in reviewable files beside tests. Reviewers can inspect scope, severity, and analyst guidance. Tests verify how the engine evaluates those fields.

**How do you prevent duplicate records from inflating alerts?**

The parser uses event identifiers, collapses identical copies, and rejects conflicting content. A JSON-aware comparison preserves value types so a Boolean and a number cannot silently become identical evidence.

**How do you distinguish an attempted change from an applied change?**

Configuration rules require the absence of a recorded error. Denied requests stay outside those configuration findings. I would still verify the resulting state and log delivery during investigation.

**How do you tune false positives?**

I require an exact rule, identity, and address plus a reason. Suppressions remain in reports. Tests verify another identity and a different rule stay active. Correlated findings require all contributing events to match.

**Why include a hunting exercise as well as tests?**

Tests check specified behavior and regressions. Hunting develops open-ended reasoning, recognition of missing context, and evidence requests. The student manually investigates a successful sign-in following repeated failures.

## Two-minute demonstration

Run commands from the repository root.

- **0:00–0:25** — State local scope and show one rule file's selection, severity, and analyst action.
- **0:25–0:55** — Run the full dataset below and expect eight active findings.
- **0:55–1:25** — Open the Markdown report and compare observed evidence with analyst interpretation.
- **1:25–2:00** — Run the normal control below and explain its zero findings.

The first command analyzes the full folder. The second analyzes the normal file.

```powershell
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/synthetic/ --output-dir reports/portfolio/all
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/synthetic/normal_activity.json --output-dir reports/portfolio/normal
```

## Five-minute demonstration

- **0:00–0:40** — Explain the problem and data flow. Show a raw event and a Sigma-style rule.
- **0:40–1:20** — Run the full dataset. Connect a high-severity finding to its rule and original evidence.
- **1:20–2:10** — Run tuning before and after below. Show four active findings becoming two active and two suppressed. Point to the retained logging alert and other identity's source alert.
- **2:10–3:30** — Use the inspection command in the hunting guide. Explain three failures, the success, self-assigned policy, StopLogging, and the denied DeleteTrail.
- **3:30–4:15** — Run the normal control and full tests. Explain what each demonstrates.
- **4:15–5:00** — Show a report-failure test and discuss policy inference and local batch limits.

The tuning commands analyze the same file with and without an approval. The last command runs all tests.

```powershell
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/tuning/approved_activity.json --output-dir reports/portfolio/tuning-before
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/tuning/approved_activity.json --config config/approved_activity.json --output-dir reports/portfolio/tuning-after
.\.venv\Scripts\python.exe -m pytest -q --basetemp .pytest-tmp
```

## Git review and commit checklist

Git records reviewed local file versions. Use this checklist when preparing a new commit in the repository.

1. Run the tests and review the measured results in résumé evidence.
2. Use `git status --short` to list files and `git diff` to review existing entries. Read newly created rules, tests, config, datasets, and guides too.
3. Run `git diff --check`. Confirm private files, generated reports, caches, and environments are excluded.
4. After approving the content, stage the named deliverables below.
5. Read the staged diff, which is the content intended for the commit.
6. If correct, commit the reviewed changes with a message that describes them.

These commands stage only the named project deliverables, then display their summary and full contents.

```powershell
git add -- .gitignore AGENTS.md LICENSE README.md pyproject.toml src tests data config docs
git diff --cached --stat
git diff --cached
```

This command records the reviewed local version after your approval.

```powershell
git commit -m "docs: prepare portfolio for publication"
```

## Three future improvements

1. Extend policy evaluation with synthetic cases for conditions, denies, and effective-permission caveats.
2. Expand normal controls and measure false positives by rule, including approval review and expiry.
3. Provide a reproducible offline dependency bundle with versions, hashes, and cross-platform installation checks.
