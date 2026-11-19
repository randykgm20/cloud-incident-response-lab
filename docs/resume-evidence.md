# Verified résumé evidence

Measured locally on November 17, 2026, using Python 3.12.14 and pytest 9.0.3 on Windows. These results describe fictional inputs and local checks. The baseline earlier in this session passed 54 tests and produced six findings from 11 events.

## Final measurements

| Measure | Verified result |
| --- | --- |
| Packaged detection rules | 8 Sigma-style JSON rules with validated identifiers and schema |
| Suspicious scenarios in the main sample folder | 8 |
| Normal control files | 2, with 3 and 2 events respectively |
| Complete sample | 15 distinct events and 8 active findings |
| Complete-sample severity counts | 6 high, 1 medium, 1 low |
| Original normal control | 3 events, 0 findings |
| Added normal control | 2 events, 0 findings |
| Automated test suite | 131 passed out of 131, a 100% pass rate on this local suite |
| Fresh ordinary-package installation | All 131 tests passed, eight packaged rule files verified, and analysis succeeded outside the source folder |
| Tuning demonstration | 3 events, 4 active findings before, 2 active and 2 suppressed after |
| Hunting exercise | 11 raw records, 10 unique events, 10 findings |
| MITRE ATT&CK technique mappings | 4 distinct identifiers, T1110.001, T1098.003, T1562.008, and T1098.001, using the catalog's historical v17 snapshot |
| Final report checks | Nine JSON/Markdown report pairs checked for counts, finding order, and original evidence |
| Sensitive-data review | 31 fixture, config, and final report files checked against selected credential and personal-data patterns, with no matches |

## What was exercised

MITRE ATT&CK stands for Adversarial Tactics, Techniques, and Common Knowledge. Mapping a behavior provides an investigation hypothesis.

The complete sample contains ConsoleLogin, CreatePolicy, AttachUserPolicy, StopLogging, PutBucketAcl, ListBuckets, and CreateAccessKey. The hunting file also includes DeleteTrail. Tests additionally exercise PutBucketPolicy.

The original six detection scenarios were preserved through regression tests. The two added rules cover recorded root identity activity and creation of a key for a different named IAM user. IAM means Identity and Access Management.

The tuning comparison retains a stopped-logging finding and an unfamiliar-source finding for another identity. Suppressed findings preserve the original records and the approval reason. The hunting exercise teaches timeline reconstruction and evidence requests.

## Verification method

The editable package and an ordinary package wheel installed using local dependency wheels with package-index access disabled. The ordinary package ran from an independent virtual environment outside the source folder. Both installations passed dependency consistency checks.

The two report formats were compared for every active and suppressed finding. Evidence was compared with the input objects using a JSON-aware representation. Source, custom-rule, and installed-package reports matched byte for byte on the complete sample.

The sensitive-data check covered key-like identifiers, private-key blocks, email-like values, and personal Windows paths. Account fields contained only the fictional identifier and fixture addresses belonged to reserved documentation ranges. This limited pattern scan complements the synthetic-data review.

## Security and complexity review

A read-only reviewer identified two issues. Regression tests reproduced both before fixes.

- Report destinations could collide with custom rule or configuration inputs. The command now rejects those paths.
- Python equality could collapse conflicting Boolean and numeric evidence. The parser now uses a JSON-aware comparison.

Tests also verify recovery from ordinary report preparation and publication failures, Markdown text escaping, symbolic-link destination rejection, malformed inputs, duplicate identifiers, and deterministic ordering.

## Accurate résumé bullet

Built a local Python cloud detection-engineering lab with eight validated Sigma-style rules, audited false-positive tuning, preserved synthetic CloudTrail evidence, and 131 passing automated tests.

## Scope of these claims

The measures describe this Windows test environment and the supplied synthetic cases. Production performance, live monitoring, automatic containment, complete Sigma support, and full cloud-permission analysis require capabilities beyond this implementation. See the limitations guide.
