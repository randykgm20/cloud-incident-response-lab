# Final local portfolio plan

## Baseline and scope

On November 17, 2026, the existing suite passed 54 tests. The original dataset yielded 11 events and six findings. The normal control yielded three events and zero findings. Git contains no commits and no remote. Preserve the original six detection behaviors and the command and report fields.

Use Python 3.11 or newer and pytest. Use synthetic files, reserved documentation addresses, and the fictional account identifier `000000000000`. Run offline. Keep credentials and generated reports out of Git. Record the final measurements after verification. The saved local snapshot is `.tmp/pre-portfolio-snapshot.zip`.

## Milestones

1. Write tests for `load_rules(directory: Path | None = None) -> list[Rule]` before implementing it in `rules.py`. Define eight JSON rule documents packaged under `src/cloud_ir_lab/rule_data/`. Validate fields, log source, selectors, condition names, parameters, mappings, and duplicate identifiers. Use named condition evaluators with documented behavior. Keep the original detector's patterns, titles, and severities.
2. Write tests for root-account activity and a successful IAM user request to create a key for a different named user. Test harmless equivalents, denied requests, missing or malformed detection fields, case-insensitive username comparison, and misleading service or operation names. Root activity is a high-priority review lead. Map cross-user key creation to Additional Cloud Credentials as a hypothesis.
3. Add `load_config(path, rule_ids)` and `apply_tuning(findings, config)`. Require rule identifier, exact identity, exact source address, and a reason for each approval. Match all contributing evidence records. Add `--config` and `--rules-dir` while preserving `--known-source`. Keep active findings in existing report fields. Add suppressed findings and a suppression count. Test narrower suppression, evidence preservation, validation, and command errors.
4. Strengthen report preparation and publication tests. Prepare and back up both files before replacement. Restore originals on a recoverable publication failure. Reject report symlinks, escape untrusted text in Markdown, and retain raw records. Sort findings deterministically. Check that preparation errors leave previous reports intact.
5. Create a mixed hunting dataset and a guide with independent event inspection, questions, timeline, evidence, assumptions, and an answer key. Update architecture, catalog, learning notes, installation, limitations, test strategy, tuning and rule-writing guides, demonstrations, and interview material.
6. Verify an offline clean installation and normal CLI entry points. Run the full suite, complete dataset, normal controls, tuning before/after, and hunting exercise. Compare both reports, inspect generated data for sensitive content, review the final tree and Git diff, then update résumé measurements.

## Review focus

- Unsupported or incorrectly typed rule fields must fail with a file location.
- Tuning must retain evidence and leave a different rule or identity active.
- Event copies and equal timestamps must produce stable ordering.
- A failure preparing or publishing either report must preserve previous reports when rollback succeeds.
- Packaged default rules must load from a fresh installation outside the source directory.

## Decisions and limits

Use JSON to avoid a YAML dependency. Named condition implementations form a deliberately limited Sigma-style schema. Add two focused rules. Keep batch analysis and the existing event model. Use an audited local suppression record. Use separate report folders for each demonstration. The report pair has recoverable rollback during ordinary filesystem errors, with power loss and concurrent writers outside its guarantees.

The user requested reviewable local changes and withheld commit and publishing approval. Leave Git history and remotes untouched.
