# Phase 1 implementation plan

Build a local command-line interface (CLI) for learning how a cloud security analyst turns log records into findings. Use Python 3.11 or newer, the standard library at runtime, and pytest for tests. Use synthetic Amazon Web Services (AWS) CloudTrail-style data and Internet Protocol (IP) addresses reserved for documentation. Keep cloud deployment and automated response for later phases.

1. Set up Git and package metadata. Keep environments, private files, and generated reports out of commits. Verify setup locally and keep installation commands in the README.
2. Write parser tests before the parser. Accept a file or a flat folder of JavaScript Object Notation (JSON) files with a CloudTrail-style `Records` array. Normalize timestamps to Coordinated Universal Time (UTC). Reject malformed files with a location, collapse identical events by event identifier, and reject conflicting copies.
3. Write detection tests before the rules. Use six synthetic suspicious scenarios and a normal control. Correlate three failures for one identity within an inclusive ten-minute window. Use a configurable list of expected source addresses. Flag wildcard Identity and Access Management (IAM) policies, self-attachment of a known administrator policy, disabled logging, and public bucket permissions.
4. Write report and CLI tests before implementing either interface. Save versioned JSON and Markdown reports. Preserve source records as evidence and label the analyst interpretation separately. Print counts and file locations. Return a nonzero status for invalid input and filesystem errors.
5. Run the full suite and the two demo commands. Confirm that the mixed folder raises six findings and normal activity raises zero. Review the reports, the ignore rules, and the code for risks. Record measured results and document how to review and commit the work.

## Design decisions

Each event retains its raw record and a few normalized fields. This keeps the rules readable and makes it possible to trace a finding to its source. Deterministic rules make the results reproducible on a clean machine. The project uses separate modules for parsing, detection, and reporting so that each can be tested through its own interface.

## Risks to check

Duplicate records can inflate counts. Events retrieved out of order can change window calculations if they are never sorted. A risky policy statement cannot establish effective permissions in isolation. An unfamiliar address can come from legitimate work. Reports contain raw evidence and must stay inside the synthetic lab.

## Suggested commit points

Commit the parser and its tests with the package setup first if you are building the project by hand. Follow with the rules and their fixtures, then reports and documentation. For the completed project, one initial Phase 1 commit gives a coherent starting point for Phase 2.
