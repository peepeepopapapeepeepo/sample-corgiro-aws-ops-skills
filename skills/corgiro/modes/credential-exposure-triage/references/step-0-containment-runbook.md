# Step 0 — Containment Runbook (printed before the first API call)

**Inputs:** the parameters from MODE.md (subject identifiers, `contained_at` if any). No AWS call has run yet except, for a `guardduty_finding_id` / `health_event_arn` subject, the single resolve call noted below.

**Hard stops / rules:**
- Print this **before** any collection call so the operator can contain while Corgiro reads.
- **Never infer identity from the key prefix.** Before Step 1 resolves the principal, print only conditional containment branches; never infer IAM user, root, role, workload role, GetSessionToken, or GetFederationToken from the key prefix. The prefix (`AKIA` vs `ASIA`) narrows which branches *could* apply, but which one is correct is unknown until Step 1.
- Every command here is **containment / mutating guidance the operator runs under their own authority** — label it `not executed by Corgiro — run under your own authority`. `CorgiroReadOnlyRole` cannot perform any of it. Corgiro never runs these.
- Printed commands never contain a raw key ID: use `$COMPROMISED_ACCESS_KEY_ID` ("the key you supplied"). All other substituted values (user name, role name, account, region) are literal only **after** Step 1 resolves them and only when they match their regex (MODE.md Safety); until then show the placeholder.
- Also write this runbook to `containment.md` in the Run Directory (masked; H3).

**Output:** `containment.md`, and the same text to the terminal.

## For a GuardDuty-finding or Health-event subject: resolve first

With `guardduty_finding_id` (+ account + region) or `health_event_arn`, print a generic banner, then make **exactly one** resolve call to fill it in, then reprint:
- `aws guardduty get-findings --detector-id <id> --finding-ids <finding-id> --region <region>` — carries the access key, principal, first/last seen, actor IP, and API. Resource type for IAM findings is `AccessKey` ([GuardDuty compromised-credentials](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)).
- `aws health describe-event-details --event-arns <arn> --region us-east-1` — the credential-exposure event names the affected key.

These are read-only and count against the budget; they are the one exception to "print before any call".

## Conditional containment branches (print all that could apply until Step 1 resolves)

Because identity is not yet known, print every branch whose prefix is consistent with the subject, flagged "applies if the key resolves to …":

### A. The subject resolves to an IAM user long-lived key (`AKIA…`)
Deactivate the key — do not delete it first (deletion erases the key's last-used data and the user's policies, destroying evidence):
```
# not executed by Corgiro — run under your own authority
aws iam update-access-key --access-key-id "$COMPROMISED_ACCESS_KEY_ID" \
  --status Inactive --user-name <USER_NAME_AFTER_STEP_1>
```
`Inactive` means the key can no longer be used for calls, while `Active` is usable ([update-access-key](https://docs.aws.amazon.com/cli/latest/reference/iam/update-access-key.html)). **Deactivation does not invalidate already-issued temporary credentials** (any `ASIA` sessions the key minted stay valid until they expire) — see branch B.

### B. The subject is a role session (`ASIA…` from `AssumeRole`)
Revoke in-flight sessions by attaching the `AWSRevokeOlderSessions` inline policy (an `aws:TokenIssueTime` `DateLessThanEquals` Deny) to the role — this requires `iam:PutRolePolicy` and **affects every session of that role issued before now, not just the attacker's** ([Revoke IAM role temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)):
```
# not executed by Corgiro — run under your own authority
aws iam put-role-policy --role-name <ROLE_NAME_AFTER_STEP_1> \
  --policy-name AWSRevokeOlderSessions \
  --policy-document '<AWSRevokeOlderSessions document — see the doc above>'
```
If the role is an IAM Identity Center permission-set role, revoke it in Identity Center instead ([Use a Deny policy to revoke active user permissions](https://docs.aws.amazon.com/singlesignon/latest/userguide/prereqs-revoking-user-permissions.html)).

### C. The subject is `ASIA…` from `GetSessionToken` / `GetFederationToken`
These are minted by an underlying IAM user. Apply an `aws:TokenIssueTime` Deny on **the user** AND deactivate the issuing `AKIA` key (branch A) — otherwise the user keeps minting new sessions.

### D. The subject is a workload role session (instance / task / function role)
Treat the workload as compromised: apply a session Deny keyed on `aws:userId`, and isolate/snapshot the workload per GuardDuty's EC2 compromise runbook ([Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)). Snapshotting is evidence preservation the operator runs — it is **not** in `handoff.md` (handoff commands are read-only); it is containment guidance here.

### E. The subject is the root user
Separate root runbook: sign in as root, delete the root access keys, and enable/rotate root MFA ([Resolve unauthorized activity](https://aws.amazon.com/premiumsupport/knowledge-center/potential-account-compromise)). Root is confirmed only when a resolved event shows `userIdentity.type == Root` or the credential-report root row has an active key — never inferred from the prefix (Step 6f).

## Common lines (print always)
- If `AWSCompromisedKeyQuarantineV2` or `AWSCompromisedKeyQuarantineV3` is already attached to the principal, AWS has already detected the exposure and opened a Support case — **do not detach it until rotation completes** ([V2](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV2.html), [V3](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV3.html)). Step 1 flags whether it is attached.
- **Do not delete the user, role, or key until Step 1 evidence is captured** — deletion erases policies and last-used data the triage depends on.
- After containment, re-run this mode with `--contained-at <timestamp>` so Step 6e can detect STILL-ACTIVE use (CloudTrail has delivery lag and the attacker may still be active).
