# Threat-hunting exercise

Threat hunting means asking a security question and examining records to assess it. A detector supplies leads. The investigator establishes what the evidence supports and what information is missing.

## Fictional scenario

A training organization asks whether `lab-investigator` performed unexpected privileged activity on January 15, 2026. The brief gives `192.0.2.10` and `198.51.100.23` as usual lab addresses. It supplies no change approvals. `data/hunting/case.json` mixes relevant events with harmless controls. Records arrive out of order and one appears twice.

The identities, account identifier, and addresses are fictional. Times use Coordinated Universal Time (UTC).

## Questions to investigate

1. How many raw records and distinct events are present? Which record is duplicated?
2. What identity and address connect the failures? How much time passes between the first and third failure?
3. What follows the failures? Does it establish who controlled the identity?
4. Who requests the administrator attachment, and who receives it?
5. Which logging change has no recorded error? Which request is denied?
6. What looks consistent with the baseline? Which additional evidence would you request?

## Inspect before running detection

This PowerShell command sends a Python program to the interpreter. `load_events` validates, deduplicates, and sorts the records. The loop prints each event's time, identifier, identity, source, operation, and error.

```powershell
@'
from pathlib import Path
from cloud_ir_lab.parser import load_events

events = load_events(Path("data/hunting/case.json"))
for event in events:
    print(
        event.timestamp.isoformat(),
        event.event_id,
        event.identity,
        event.source_ip,
        event.name,
        event.error_code or "no recorded error",
    )
'@ | .\.venv\Scripts\python.exe -
```

Read requestParameters and responseElements in the original file. The next command independently counts raw records and prints the failed-sign-in records, including copies.

```powershell
@'
import json
from pathlib import Path

records = json.loads(Path("data/hunting/case.json").read_text(encoding="utf-8"))["Records"]
print("Raw record count", len(records))
for record in records:
    response = record.get("responseElements") or {}
    if response.get("ConsoleLogin") == "Failure":
        print(record["eventID"], record["eventTime"])
'@ | .\.venv\Scripts\python.exe -
```

Write your conclusions under **facts**, **interpretations**, and **assumptions**. Then compare them with detection output using the following command. It writes to a separate report folder.

```powershell
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/hunting/case.json --output-dir reports/portfolio/hunt
```

## Answer key and timeline

There are 11 raw records and 10 distinct events. `hunt-02` appears twice. Deduplication keeps its second copy from inflating the failure count.

| UTC time | Event | Recorded fact | Interpretation |
| --- | --- | --- | --- |
| 09:00 | `hunt-00` | `lab-operator` lists buckets from `192.0.2.10`. | Consistent with the provided origin baseline. |
| 09:01, 09:03, 09:05 | `hunt-01` through `hunt-03` | Three ConsoleLogin failures for `lab-investigator` from `203.0.113.88` within four minutes. | Supports investigation of password guessing or user error. |
| 09:06 | `hunt-04` | ConsoleLogin success for the same identity and source. | Concern increases after the failures. Who controlled the identity remains unknown. |
| 09:07 | `hunt-05` | The identity attaches AdministratorAccess to its own username without an error code. | Potential privilege increase. Prior access and authorization need review. |
| 09:08 | `hunt-06` | StopLogging names `lab-hunt-trail` without an error code. | Potential audit-coverage reduction. Check actual delivery and alternate trails. |
| 09:09 | `hunt-07` | DeleteTrail returns AccessDenied. | Evidence of attempted deletion. This record cannot establish deletion. |
| 09:10 | `hunt-08` | `lab-operator` lists buckets from `198.51.100.23`. | Consistent with the provided origin baseline. |
| 09:11 | `hunt-09` | `lab-operator` requests a key for its own username. | Outside the cross-user key rule. Authorization would still matter during investigation. |

**Facts** come from named fields and recorded outcomes. The relevant identity is `arn:aws:iam::000000000000:user/lab-investigator`. Seven events share `203.0.113.88`.

**Interpretations** include possible password guessing, privilege escalation, and defense evasion. The sequence supports investigation. The records alone cannot establish an attacker, data theft, or an authorization violation.

**Assumptions** include the baseline's reliability and the supplied event set's completeness. There are no approvals, full authentication context, object-access logs, or complete permission evaluation.

The detector produces 10 active findings from 10 unique events, consisting of seven unfamiliar-source findings, one repeated-failure finding, one self-assigned-administrator finding, and one stopped-logging finding. The successful sign-in following failures is a manual investigation step.

## Evidence to request next

In a separately authorized investigation, request the change approval, identity-owner confirmation, authentication context, previous permissions, subsequent activity, and independent log-delivery evidence. Explain what question each item answers. The exercise ends with that investigation plan.
