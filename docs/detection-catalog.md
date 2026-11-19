# Detection catalog

Eight Sigma-style rule files under src/cloud_ir_lab/rule_data define these detections. See the rule-writing guide for the supported schema. These rules evaluate synthetic Amazon Web Services (AWS) CloudTrail-style logs. Every rule starts with a valid event containing the fields listed in the [architecture](architecture.md). Configuration rules treat a nonempty `errorCode` as a rejected operation. Evidence is the source record or records. Severity, technique mapping, and interpretation are analyst judgments. MITRE ATT&CK stands for Adversarial Tactics, Techniques, and Common Knowledge. The identifiers below use the ATT&CK v17 naming and tactic labels as a reference snapshot for the lab.

## Repeated console authentication failures

- **Objective and threat behavior** — Identify a cluster of unsuccessful sign-ins that could signal password guessing.
- **Fields and logic** — Match `signin.amazonaws.com / ConsoleLogin` with `responseElements.ConsoleLogin` equal to `Failure`. Group by normalized identity and alert on the first group of three within ten minutes, inclusive, per identity per run. Evidence contains the three events. The record describes sign-ins from one or more sources.
- **Severity and mapping** — Medium because guessing can precede account access and the same pattern can come from user error. `T1110.001` Password Guessing, Credential Access.
- **False positives and investigation** — Typos and stale passwords. Check source addresses, nearby successful sign-ins, and the identity owner's expected activity.
- **Test coverage** — `test_synthetic_scenario[failed_logins…]` and `test_login_threshold_is_per_identity_within_ten_minutes`.

## Overly permissive IAM policy created

- **Objective and threat behavior** — Identify a newly created Identity and Access Management (IAM) policy that could grant broad access if attached and effective.
- **Fields and logic** — Match `iam.amazonaws.com / CreatePolicy`. Read `requestParameters.policyDocument` as an object or encoded JSON string. Look for an `Allow` statement with both `Action` and `Resource` containing the full wildcard `*` and no `Condition` field. `policyName` identifies the resource when supplied.
- **Severity and mapping** — High because the proposed grant covers all actions and resources. Unmapped because the creation of a policy alone does not establish adversary behavior or attachment.
- **False positives and investigation** — Approved broad automation policies can match. Check change authorization and attachments, then evaluate the complete policy and permissions boundaries before concluding what access it grants.
- **Test coverage** — `test_synthetic_scenario[overly_permissive_policy…]` and `test_wildcard_policy_requires_unconditional_allow`.

## Identity attached an administrator policy to itself

- **Objective and threat behavior** — Flag an identity granting itself a policy associated with administrative access.
- **Fields and logic** — Match `iam.amazonaws.com / AttachUserPolicy` for an `IAMUser` when `userIdentity.userName` and `requestParameters.userName` agree, ignoring case, and `policyArn` is the AWS-managed `AdministratorAccess` Amazon Resource Name (ARN). The caller's identity is also the affected user.
- **Severity and mapping** — High because the change can grant powerful privileges. `T1098.003` Additional Cloud Roles, Persistence and Privilege Escalation.
- **False positives and investigation** — Approved setup or break-glass maintenance. Check approval, compare previous and resulting permissions, and review subsequent privileged actions.
- **Test coverage** — `test_synthetic_scenario[privilege_escalation…]` and `test_assigning_another_user_does_not_match_self_assignment`.

## CloudTrail logging stopped or trail deleted

- **Objective and threat behavior** — Identify changes that may reduce audit coverage and hide activity.
- **Fields and logic** — Match `cloudtrail.amazonaws.com / StopLogging` or `DeleteTrail`. The request's `name` identifies the affected trail when available.
- **Severity and mapping** — High because the loss of records can prevent reconstruction of an incident. `T1562.008` Disable or Modify Cloud Logs, Defense Evasion, using the stated ATT&CK snapshot.
- **False positives and investigation** — Approved trail retirement or a migration. Check the change window, alternate trails, log delivery, and the last record received.
- **Test coverage** — `test_synthetic_scenario[logging_disabled…]` and `test_deleting_trail_matches_logging_rule`.

## S3 bucket permission may allow public access

- **Objective and threat behavior** — Flag a change to an Amazon Simple Storage Service (S3) bucket that could broaden access.
- **Fields and logic** — Match `s3.amazonaws.com / PutBucketAcl` with a canned access control list (ACL) of `public-read`, `public-read-write`, or `authenticated-read` in `x-amz-acl` or `acl`. The authenticated setting covers the broadly shared AWS Authenticated Users group. Also match `PutBucketPolicy` when `bucketPolicy` contains an unconditional `Allow` with a wildcard principal and a supported read or list action (`s3:GetObject`, `s3:ListBucket`, `s3:*`, or `*`). `bucketName` identifies the bucket when available.
- **Severity and mapping** — High because unintended public access can expose data. Unmapped because this event records a permission change and contains no evidence of object access.
- **False positives and investigation** — Approved public content or controls that override the grant. Verify ownership, the complete permissions configuration, Block Public Access, and access logs. This rule covers the listed policy and canned ACL patterns.
- **Test coverage** — `test_synthetic_scenario[public_bucket…]` and `test_public_bucket_policy_requires_public_principal`.

## Activity from an unfamiliar source address

- **Objective and threat behavior** — Surface activity from outside a known set of Internet Protocol (IP) addresses. Someone using stolen credentials may operate from a new address.
- **Fields and logic** — Compare the event's `sourceIPAddress` with the run's expected addresses if the field contains a valid IPv4 or IPv6 address. Service hostnames are left out of the comparison. The default list contains two synthetic addresses. A finding is emitted per matching event. Use a resource ARN or bucket name when present.
- **Severity and mapping** — Low because unfamiliar origin alone is weak evidence. Unmapped because the address does not establish a particular technique.
- **False positives and investigation** — Remote workers, approved virtual private networks (VPNs), or new egress addresses. Verify expected routes and examine nearby events for the same identity.
- **Test coverage** — `test_synthetic_scenario[unusual_source…]`, `test_ip_baseline_can_be_replaced`, and `test_service_hostname_is_not_treated_as_unusual_ip`.

The normal control has a successful sign-in, an operation from a known address, and a scoped policy. `test_normal_activity_does_not_alert` verifies that it is quiet. `test_rejected_change_does_not_claim_configuration_changed` covers denied operations for all four configuration-change rules.

## Root-account activity recorded

- **Objective and threat behavior** — Surface use or attempted use of a root identity for priority review.
- **Fields and logic** — Require userIdentity.type exactly Root. Match every validated event with that type, including denied requests. The recorded identity is the affected resource.
- **Severity and mapping** — High because root privileges can have broad impact. Unmapped because root use alone does not establish adversary behavior.
- **False positives and investigation** — Approved recovery or an account task requiring root. Check operator, authentication context, authorization, outcome, and nearby activity.
- **Test coverage** — test_root_activity_includes_denied_attempts, test_root_rule_requires_exact_recorded_root_type, and the root fixture test.

## Access key created for another IAM user

- **Objective and threat behavior** — Identify a credential-creation request for a different named user that may create another access path.
- **Fields and logic** — Require iam.amazonaws.com, CreateAccessKey, IAMUser type, valid actor and target usernames, different names ignoring case, and no error code. Names must use the supported IAM username character set and have 1–64 characters. The target username is the resource. The fixture contains no key value.
- **Severity and mapping** — High because a new credential can enable access under another user's permissions. T1098.001 Additional Cloud Credentials, Persistence and Privilege Escalation, is a behavior hypothesis using the catalog's reference snapshot.
- **False positives and investigation** — Approved administrator-led key rotation. Check the approval and target permissions, then examine subsequent activity in a separately authorized investigation.
- **Test coverage** — test_key_creation_for_another_user_preserves_target_and_evidence, username-boundary tests, outcome/service/operation tests, missing-actor tests, and malformed-timestamp tests.

## Tuning and control evidence

The original normal control remains quiet. The added normal file contains same-user key creation and a known-source operation. The tuning demonstration preserves a stopped-logging finding while recording approved unfamiliar-source findings under suppressed_findings. Review docs/tuning-guide.md.

## Mapping interpretation

MITRE mappings describe possible behaviors. The policy and public-bucket rules remain unmapped because their records alone have insufficient behavioral specificity. This project preserves its documented v17 snapshot for reproducibility and leaves a current-reference mapping review as a future maintenance task.
