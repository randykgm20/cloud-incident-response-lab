# Rule-writing guide

A hard-coded detection puts its configuration and explanation inside Python. Detection-as-code stores those decisions in a separate file that can be reviewed and tested. The Python engine still implements the condition mechanics.

These JSON files borrow familiar Sigma concepts such as `logsource`, `detection`, and `level`. Sigma is an open log-detection rule format. This lab's supported schema is the subset below. Official Sigma expression parsing, YAML rules, modifiers, and backend conversion require capabilities beyond this engine.

## Read a rule

Open `src/cloud_ir_lab/rule_data/repeated-auth-failure.json`. Its fields mean the following.

| Field | Meaning and allowed values |
| --- | --- |
| `id` | A unique lowercase identifier with hyphen-separated words. |
| `title` | A readable finding name. |
| `description` | The analyst interpretation placed in the report. Keep it consistent with the condition. |
| `status` | `experimental`, `test`, or `stable` as author metadata. Every loaded rule is evaluated. |
| `logsource` | Exactly `{"product":"aws","service":"cloudtrail"}`. |
| `detection.selection` | Exact matches for `eventSource`, `eventName`, `userIdentity.type`, or `responseElements.ConsoleLogin`. Each value is a nonempty string or list of nonempty strings. Empty selection evaluates every validated event. |
| `detection.condition` | One of the named conditions listed below. |
| `detection.parameters` | Required object. Only the repeated-failure condition accepts parameters. |
| `level` | `low`, `medium`, or `high`. |
| `attack` | Null or exactly `technique_id`, `technique`, and `tactic` as strings. The identifier follows a form such as `T1110.001`. |
| `falsepositives` | Nonempty array explaining plausible legitimate causes. |
| `recommended_action` | A specific investigation action, without automatic response. |
| `notes` | Nonempty array explaining limitations or reference context. |

All fields listed in the table are required. Extra fields at supported schema levels, unsupported selectors, duplicate identifiers, and malformed JSON produce an error naming the file. Empty or missing rule directories fail clearly. The loader validates syntax and supported values. The author must verify semantic correctness and technique attribution.

## Supported condition mechanics

| Condition | Mechanics beyond selection |
| --- | --- |
| `repeated_console_failures` | Group selected events by identity. Emit the first window meeting the threshold per identity per run. `threshold` is an integer from 2 to 1000. `window_minutes` is an integer from 1 to 1440, with an inclusive time boundary. |
| `unconditional_wildcard_policy` | Require no error and a policy statement allowing `*` action and `*` resource with no Condition field. |
| `self_assigned_admin` | Require no error, an IAM user whose username equals the target ignoring case, and the exact AWS-managed AdministratorAccess policy. |
| `logging_disabled` | Selected events without a recorded error produce a finding. Select StopLogging and DeleteTrail from the correct service. |
| `public_bucket_permissions` | Require no error and the documented public canned access control list or supported public bucket-policy read/list grant. |
| `unusual_source` | Flag a valid Internet Protocol (IP) address absent from the effective baseline. Hostnames do not qualify. |
| `root_activity` | Selected events produce a review lead, including denied activity. Use `userIdentity.type` equal to `Root`. |
| `cross_user_access_key` | Require no error and valid, different actor and target IAM usernames. Use the IAMUser type and the IAM CreateAccessKey operation in selection. |

Selectors provide essential scope. For example, a `logging_disabled` condition with an empty selector would mislabel unrelated successful requests. The bundled rule and tests demonstrate the required selection. Named conditions intentionally keep complex event relationships in Python.

## Make a small change safely

1. Read the condition, catalog entry, and current test together.
2. Write a test for the intended behavior and run it. Confirm that it fails for the expected reason.
3. Change the smallest relevant field or condition implementation.
4. Run the focused tests, then the full suite.
5. Compare the report with the source record and review the change in Git.

To evaluate another rule folder, the following command loads and validates every JSON rule in the supplied folder before reading the events. It also demonstrates using the bundled rule folder explicitly.

```powershell
.\.venv\Scripts\python.exe -m cloud_ir_lab.cli analyze data/synthetic/ --rules-dir src/cloud_ir_lab/rule_data --output-dir reports/portfolio/custom-rules
```

The suite's `test_changed_rule_threshold_changes_real_detection` changes the threshold in a temporary rule and verifies a real finding. `test_rule_selection_is_evaluated` changes the selected operation and verifies that it stops matching the original records.
