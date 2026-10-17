# Step 0 — Containment Runbook (printed before the first API call)

**Inputs:** the parameters from MODE.md (subject identifiers, `contained_at` if any). No AWS call has run yet except, for a `guardduty_finding_id` / `health_event_arn` subject, the single resolve call noted below.

**Hard stops / rules:**
- Print this **before** any collection call so the operator can contain while Corgiro reads.
- **Never infer identity from the key prefix.** Before Step 1 resolves the principal, print only conditional containment branches; never infer IAM user, root, role, workload role, GetSessionToken, or GetFederationToken from the key prefix. The prefix (`AKIA` vs `ASIA`) is **not** a branch selector — an `AKIA` may be an IAM-user or a root key, and an `ASIA` may be a role session, a federation/session-token session, or a workload-role session; which branch is correct is unknown until Step 1 resolves the principal.
- Every command here is **containment / mutating guidance the operator runs under their own authority** — label it `not executed by Corgiro — run under your own authority`. `CorgiroReadOnlyRole` cannot perform any of it. Corgiro never runs these.
- Printed commands never contain a raw key ID: use the subject's `$COMPROMISED_ACCESS_KEY_ID_N` placeholder ("the key you supplied"). All other substituted values (user name, role name, account, region) are literal only **after** Step 1 resolves them and only when they match their regex (MODE.md Safety); until then show the placeholder.
- Also write this runbook to `containment.md` in the Run Directory (key IDs masked per MODE.md Safety).
- **No-subject discovery path:** there is no key to contain yet, so Step 0 prints only the **generic banner** (all branches A-E with their "applies if" conditions) as standing guidance, and writes it to `containment.md`. The operator contains after Step 1b surfaces suspects and they pick subjects; the targeted re-run then prints the resolved branch.

**Output:** `containment.md`, and the same text to the terminal.

## For a GuardDuty-finding or Health-event subject: resolve first

With `guardduty_finding_id` (+ account + region) or `health_event_arn`, print a generic banner, then make the resolve call(s) to fill it in, then reprint:
- **GuardDuty needs a detector ID, which the parameters do not carry** ([GetFindings](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindings.html) requires `--detector-id`). So, in the given account/region: (1) `aws guardduty list-detectors --region=<region> --no-paginate` (a counted call), (2) validate the returned detector ID against `\A[0-9a-f]{32}\z` and the supplied finding ID against `\A[0-9a-f]{32,64}\z` before use, then (3) `aws guardduty get-findings --detector-id=<validated detector id> --finding-ids=<validated finding id> --region=<region> --no-paginate`. The finding carries the access key, principal, first/last seen, actor IP, and API; resource type for IAM findings is `AccessKey` ([GuardDuty compromised-credentials](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)).
- For a Health event, validate the supplied `health_event_arn` against `\Aarn:aws[a-z-]*:health:[a-z0-9-]*::event/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+\z` before use, then make **two** calls: `aws health describe-event-details --event-arns=<arn> --region=us-east-1` returns the event **description** ([DescribeEventDetails](https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeEventDetails.html)); then `aws health describe-affected-entities --filter='{"eventArns":["<arn>"]}' --region=us-east-1` returns the affected entities, whose `entities[].entityValue` the API documents only as "the ID of the affected entity" ([DescribeAffectedEntities](https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeAffectedEntities.html) → [AffectedEntity](https://docs.aws.amazon.com/health/latest/APIReference/API_AffectedEntity.html)). Treat `entityValue` as a **candidate** only: accept it as the subject key (`key_status: valid`) **iff** it matches `\A(AKIA|ASIA)[0-9A-Z]{16}\z`; otherwise set `key: null` with `key_status: candidate-rejected` (non-key value) or `not-observable` (no entity) and require an operator-supplied `access_key_id` before fan-out. Corgiro does not assert from memory that a credential-exposure event's `entityValue` is an access-key ID.

These are read-only and count against the budget (per MODE.md "Budget accounting"); they are the one exception to "print before any call".

## Conditional containment branches (print the generic banner, then the branch Step 1 resolves)

Identity is unknown before Step 1, and the key **prefix never selects a branch** — an `AKIA` can be an IAM-user key or a root key, and an `ASIA` can be a role session, a federation/session-token session, or a workload-role session. So:
- **Before Step 1 resolves** (and for the no-subject discovery path, which has no key yet): print a **generic banner** listing all branches A-E with the one-line condition under which each applies ("if the key resolves to an IAM-user key …", "… to a role session …", etc.), and instruct the operator to wait for the resolved branch unless they already know the identity.
- **After Step 1 resolves**: reprint only the branch that matches the resolved principal type (and fill its validated names). Root is branch E and is selected only by `userIdentity.type == Root` or an active root key in the credential report — never by the `AKIA` prefix.

Each branch below carries its "applies if" condition explicitly.

### A. The subject resolves to an IAM user long-lived key (`AKIA…`, `userIdentity.type=IAMUser`)
Deactivate the key — do not delete it first. Deactivation neutralizes the key (`update-access-key --status Inactive`) while leaving the key, its metadata, and the user's policies in place for the triage to read; deletion is irreversible and discards evidence, so defer it until Step 1 has captured what it needs. ([update-access-key](https://docs.aws.amazon.com/cli/latest/reference/iam/update-access-key.html); [delete-access-key](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteAccessKey.html).)
```
# not executed by Corgiro — run under your own authority
aws iam update-access-key --access-key-id="$COMPROMISED_ACCESS_KEY_ID_N" \
  --status=Inactive --user-name=<USER_NAME_AFTER_STEP_1>
```
(For a **root** key — branch E — the same call is run **without** `--user-name`, which operates on the caller's own root credentials; see [update-access-key](https://docs.aws.amazon.com/cli/latest/reference/iam/update-access-key.html).) `Inactive` means the key can no longer be used for calls, while `Active` is usable. **Deactivation does not invalidate already-issued temporary credentials** (any `ASIA` sessions the key minted stay valid until they expire) — see branch B.

### B. The subject resolves to a role session (`ASIA…`, `userIdentity.type=AssumedRole` from `AssumeRole`)
Revoke in-flight sessions by attaching the `AWSRevokeOlderSessions` inline policy — an `aws:TokenIssueTime` `DateLessThanEquals` Deny — to the role. This requires `iam:PutRolePolicy` and **affects every session of that role issued before `<ISO8601 revoke-cutoff>`, not just the attacker's** ([Revoke IAM role temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)). The only placeholders are `<ROLE_NAME_AFTER_STEP_1>` (validated IAM name) and `<ISO8601 revoke-cutoff>` (the containment timestamp); the policy body is a fixed template written to a file and passed by `file://`:
```
# not executed by Corgiro — run under your own authority
cat > /tmp/revoke-older-sessions.json <<'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSRevokeOlderSessions",
      "Effect": "Deny",
      "Action": ["*"],
      "Resource": ["*"],
      "Condition": { "DateLessThan": { "aws:TokenIssueTime": "REVOKE_CUTOFF_ISO8601" } }
    }
  ]
}
POLICY
# edit REVOKE_CUTOFF_ISO8601 to your containment timestamp, then:
aws iam put-role-policy --role-name=<ROLE_NAME_AFTER_STEP_1> \
  --policy-name=AWSRevokeOlderSessions \
  --policy-document=file:///tmp/revoke-older-sessions.json
```
(The heredoc is single-quoted (`'POLICY'`) so nothing in the body is shell-expanded.) If the role is an IAM Identity Center permission-set role, revoke it in Identity Center instead ([Use a Deny policy to revoke active user permissions](https://docs.aws.amazon.com/singlesignon/latest/userguide/prereqs-revoking-user-permissions.html)).

### C. The subject resolves to `ASIA…` from `GetSessionToken` / `GetFederationToken`
These are minted by an underlying IAM user. Apply an `aws:TokenIssueTime` Deny on **the user** AND deactivate the issuing `AKIA` key (branch A) — otherwise the user keeps minting new sessions.

### D. The subject resolves to a workload role session (instance / task / function role; `AssumedRole` whose role is a workload role)
Treat the workload as compromised: apply a session Deny keyed on `aws:userId`, and isolate/snapshot the workload per GuardDuty's EC2 compromise runbook ([Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)). Snapshotting is evidence preservation the operator runs — it is **not** in `handoff.md` (handoff commands are read-only); it is containment guidance here.

### E. The subject resolves to the root user (`userIdentity.type=Root`, or an active root key in the credential report)
Separate root runbook: sign in as root, delete the root access keys, and enable/rotate root MFA ([Resolve unauthorized activity](https://aws.amazon.com/premiumsupport/knowledge-center/potential-account-compromise)). Root is confirmed only when a resolved event shows `userIdentity.type == Root` or the credential-report root row has an active key — never inferred from the prefix (Step 6f).

## Common lines (print always)
- If `AWSCompromisedKeyQuarantineV2` or `AWSCompromisedKeyQuarantineV3` is already attached to the principal, AWS has already detected the exposure and opened a Support case — **do not detach it until rotation completes** ([V2](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV2.html), [V3](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV3.html)). Step 1 flags whether it is attached.
- **Do not delete the user, role, or key until Step 1 evidence is captured.** Deletion is irreversible: deleting the **IAM user** removes that user's inline policies, group memberships, and attachment records, and deleting the **access key** discards it and its metadata. Deactivate (not delete) during containment so the triage can still read the evidence.
- After containment, re-run this mode with `--contained-at <timestamp>` so Step 6e can detect STILL-ACTIVE use (CloudTrail has delivery lag and the attacker may still be active).
