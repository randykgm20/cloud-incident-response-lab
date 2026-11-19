# Limitations and safety boundaries

## Supported use

The project is an educational, local batch analyzer for synthetic AWS CloudTrail-style files. AWS means Amazon Web Services. Fictional inputs, a small event set, and analyst-reviewed findings define its operating scope. Its security contribution is tested detection behavior and traceable evidence on those inputs.

Live account monitoring, automatic incident containment, real credentials, deployment, and continuous operations fall outside its capabilities. A production Security Information and Event Management (SIEM) platform also needs collection, indexing, access control, availability, retention, and operational support beyond this project.

## Interpretation limits

- A finding is a pattern match. Authorization, effective permissions, exposure, and compromise require additional investigation.
- Policy checks cover documented wildcard and public read/list patterns. Explicit denies, conditions, boundaries, organization policies, Block Public Access, and the full policy language need separate analysis.
- Embedded policy strings use a basic JSON decoder in the policy helper. Malformed strings are unmatched. Duplicate keys inside an encoded policy string use the decoder's last value. Outer event, rule, and configuration JSON reject duplicate keys.
- Root detection relies on a recorded identity type. Cross-user key detection covers named IAMUser actors and named targets. Role sessions, root-issued key creation, missing targets, and account-wide key state need additional logic.
- Repeated failures require a stable identity and report only its first qualifying window per run. Redacted or inconsistent identities can prevent useful correlation.
- An unfamiliar address can represent legitimate activity. Hostnames remain outside address comparison. The baseline is an explicit address list.
- The catalog uses a documented ATT&CK v17 reference snapshot. MITRE ATT&CK is Adversarial Tactics, Techniques, and Common Knowledge. Technique mappings are hypotheses, and their historical names and tactic labels require a reference review before future publication.
- Sigma-style files use a limited local schema with named Python conditions. Full official Sigma compatibility requires a broader implementation.

## Evidence and operational limits

- The parser validates core fields and loads the batch into memory. Full real-world CloudTrail variations, large-scale ingestion, cryptographic integrity, and chain of custody need additional work.
- Reports retain complete input records. The operator is responsible for supplying fictional records. Avoid personal information, account data, credentials, military information, and operational details.
- Rule metadata and tuning approvals are trusted local project files. Their meaning and continued appropriateness need review even when schema validation succeeds.
- Report recovery covers ordinary preparation and publication failures with one writer. Power loss, concurrency, or a failed rollback can leave inconsistent reports. A rollback failure returns a clear error. Use distinct output folders and inspect failed runs.
- Report content is deterministic for the same validated event set, rules, and effective configuration. The original evidence preserves differences in original records.
- Offline dependency installation requires compatible approved wheels and Python 3.11 or newer. Runtime and dependency paths vary by machine.

## Authorized next steps

Keep analysis in the repository's local test environment. Use synthetic records and reserved documentation addresses. Keep reports local and ignored by Git. Any future cloud collection, paid resources, real evidence, external transfer, or response action would require a separately approved scope.
