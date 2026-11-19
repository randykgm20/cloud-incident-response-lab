# False-positive tuning

A false positive is a detection explained by legitimate activity. Think of a smoke alarm reacting while someone cooks. The alarm sensed something worth checking, and the investigation established a harmless cause.

In this fictional example, change LAB-CHANGE-001 approves `lab-operator` using `203.0.113.77` as a test egress address. The address is reserved for documentation. The approval affects the unfamiliar-source rule for that identity and address.

## Inspect the input and approval

`data/tuning/approved_activity.json` has three events.

| Event | Activity | Before tuning |
| --- | --- | --- |
| `lab-tuning-001` | The approved user lists buckets from the new address. | One unfamiliar-source finding. |
| `lab-tuning-002` | The same user requests StopLogging from that address. | A logging finding and an unfamiliar-source finding. |
| `lab-tuning-003` | Another user lists buckets from the same address. | One unfamiliar-source finding. |

The config file contains a schema version and an approvals array. Each approval requires an exact rule identifier, identity, address, and nonempty reason. Address ranges and identity wildcard matching are outside this schema. Duplicate approvals and unknown rule identifiers are rejected.

The approval is a fictional training assertion. In actual analysis, the evidence supporting an approval would need its own review. An approved network origin does not authorize all actions from that origin.

## Run the controlled comparison

The first command analyzes all three events with the baseline. The second uses the same events with the local approval. Separate output folders retain both results.

```powershell
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/tuning/approved_activity.json --output-dir reports/portfolio/tuning-before
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/tuning/approved_activity.json --config config/approved_activity.json --output-dir reports/portfolio/tuning-after
```

Expect four active findings before tuning. After tuning there are two active findings and two suppressed findings. The high-severity logging alert remains active. The unfamiliar-source alert for `lab-other` also remains active.

Open both JSON reports. Compare `finding_count`, `suppressed_count`, and each event identifier under `evidence`. Suppressed findings retain the original records and add `suppression_reason`. The Markdown report includes the same audited suppressions.

## Review scope and expiry

An approval must match every contributing record of a correlated finding. Approving one address cannot suppress a three-event failure finding that includes another address.

Approvals have no automatic expiry or author authentication. Review their continued justification manually before each reuse. Keep them fictional and local. The legacy `--known-source` option changes the initial baseline and is recorded in `analysis_context`. Use the approvals mechanism for per-finding tuning with recorded reasons.

## Interview explanation

“I tuned the source rule with an exact rule, identity, and address approval. I retained the suppressed records and reason in the report, then tested that the stopped-logging alert and another identity's source alert stayed active.”
