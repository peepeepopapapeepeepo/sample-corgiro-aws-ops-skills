# Step 0 — Containment Runbook (printed before the first API call)

**Inputs:** the parameters from MODE.md (subject identifiers, `contained_at` if any). No AWS call has run yet except, for a `guardduty_finding_id` / `health_event_arn` subject, the resolve calls noted below (GuardDuty needs two: `list-detectors` then `get-findings`; Health needs two: `describe-event-details` then `describe-affected-entities`).

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
- **GuardDuty needs a detector ID, which the parameters do not carry** ([GetFindings](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindings.html) requires `--detector-id`). So, in the given account/region: (1) `aws guardduty list-detectors --region=<region> --no-paginate` (a counted call), (2) validate the returned detector ID and the supplied finding ID as opaque IDs — length 1-300 and charset `[A-Za-z0-9_-]` only (fail closed; AWS does not publish a stricter format guarantee, so do not assume a 32-hex shape), then (3) `aws guardduty get-findings --detector-id=<validated detector id> --finding-ids=<validated finding id> --region=<region> --no-paginate`. The finding carries the access key, principal, first/last seen, actor IP, and API; resource type for IAM findings is `AccessKey` ([GuardDuty compromised-credentials](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)).
- For a Health event, validate the supplied `health_event_arn` with `re.fullmatch` body `arn:aws[a-z-]*:health:[a-z0-9-]*:[0-9]*:event/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+` (the account field is **optional** on Health event ARNs — it may be empty — so the account segment is `[0-9]*`) before use, then make **two** calls: `aws health describe-event-details --event-arns=<arn> --region=us-east-1` returns the event **description** ([DescribeEventDetails](https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeEventDetails.html)); then `aws health describe-affected-entities --filter='{"eventArns":["<arn>"]}' --region=us-east-1` returns the affected entities, whose `entities[].entityValue` the API documents only as "the ID of the affected entity" ([DescribeAffectedEntities](https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeAffectedEntities.html) → [AffectedEntity](https://docs.aws.amazon.com/health/latest/APIReference/API_AffectedEntity.html)). Treat `entityValue` as a **candidate** only: accept it as the subject key (`key_status: valid`) **iff** it matches `re.fullmatch` body `(AKIA|ASIA)[0-9A-Z]{16}`; otherwise set `key: null` with `key_status: candidate-rejected` (non-key value) or `not-observable` (no entity) and require an operator-supplied `access_key_id` before fan-out. Corgiro does not assert from memory that a credential-exposure event's `entityValue` is an access-key ID.
  - **Health is a global service with its endpoint in `us-east-1`; on a `us-east-1` impairment it fails over to `us-east-2`.** The resolve calls target `us-east-1`; if they fail, retry against `us-east-2` ([Health API multi-Region](https://docs.aws.amazon.com/health/latest/ug/health-api.html)).

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
Revoke in-flight sessions by attaching the `AWSRevokeOlderSessions` inline policy — an `aws:TokenIssueTime` `DateLessThan` Deny — to the role. This requires `iam:PutRolePolicy` and **affects every session of that role issued before the revoke cutoff, not just the attacker's** ([Revoke IAM role temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)). The block below has exactly two values Corgiro fills, both as **quoted literals on the first two lines** (never left as unset variables): the revoke cutoff and the role name. The **revoke cutoff is the containment time plus 30 seconds** (or later), not the containment time itself — when AWS's console revokes sessions it denies sessions issued up to "approximately 30 seconds into the future" to cover policy-propagation delay, so a cutoff exactly at containment time can miss a session acquired or renewed during propagation ([revoke-sessions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)). Corgiro generates the cutoff as an ISO-8601 literal (UTC, `Z` suffix), validates it against the `ISO8601_TS` body in [`step-7-report-handoff.md`](step-7-report-handoff.md) → "Per-type substitution regexes" before writing it, and fills the role name only after Step 1 resolved it and it matched the IAM-name body `[A-Za-z0-9][A-Za-z0-9_+=.@-]{0,63}`. Until Step 1 resolves, the role-name line shows the placeholder `<ROLE_NAME_AFTER_STEP_1>` and the block must not be run. **Run the block as a saved script, not an interactive paste:** save it as `revoke.sh` and run `bash revoke.sh`. A `: "${VAR:?msg}"` guard aborts a *script* on an empty value but, pasted line by line into an interactive shell, only fails that one line and lets the rest run; and an *unresolved placeholder* like `<ROLE_NAME_AFTER_STEP_1>` is non-empty, so the empty-check alone would pass it through. The block therefore (a) is meant to be run as a script, (b) **chains every step with `&&`** so any failure stops the chain before `put-role-policy`, and (c) **rejects any value still containing `<`** (an unfilled placeholder) in addition to the empty check. The policy body is a fixed template written to a `mktemp` file created under `umask 077` and passed by `file://`:
```
#!/bin/bash
# revoke.sh — not executed by Corgiro; save and run as `bash revoke.sh` under your own authority
set -eu
REVOKE_CUTOFF_ISO8601='2026-10-10T10:30:30Z'   # Corgiro-generated literal: containment time + 30 s, regex-validated
ROLE_NAME='<ROLE_NAME_AFTER_STEP_1>'           # Corgiro fills the validated IAM role name after Step 1
# guards: reject empty AND reject any value still containing '<' (an unfilled placeholder)
: "${REVOKE_CUTOFF_ISO8601:?cutoff literal missing}" && : "${ROLE_NAME:?role name missing}" &&
case "$REVOKE_CUTOFF_ISO8601$ROLE_NAME" in *"<"*) echo "unfilled placeholder present; refusing to run" >&2; exit 1 ;; esac &&
umask 077 &&
POLICY_FILE="$(mktemp -t revoke-older-sessions.XXXXXX.json)" &&
cat > "$POLICY_FILE" <<POLICY &&
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSRevokeOlderSessions",
      "Effect": "Deny",
      "Action": ["*"],
      "Resource": ["*"],
      "Condition": { "DateLessThan": { "aws:TokenIssueTime": "$REVOKE_CUTOFF_ISO8601" } }
    }
  ]
}
POLICY
aws iam put-role-policy --role-name="$ROLE_NAME" \
  --policy-name=AWSRevokeOlderSessions \
  --policy-document="file://$POLICY_FILE"
```
(The two literals on the first lines are the only values that change between runs; `set -eu` plus the `&&` chain and the `<`-rejecting guard stop the script before `put-role-policy` if a value is empty or still a placeholder; the `mktemp`+`umask 077` keep the policy file private.) If the role is an IAM Identity Center permission-set role, revoke it in Identity Center instead ([Use a Deny policy to revoke active user permissions](https://docs.aws.amazon.com/singlesignon/latest/userguide/prereqs-revoking-user-permissions.html)).

### C. The subject resolves to `ASIA…` from `GetSessionToken` / `GetFederationToken`
These are minted by an underlying IAM user. Apply an `aws:TokenIssueTime` Deny on **the user** (same policy body and same cutoff rule as branch B — containment time + 30 s — attached with `iam put-user-policy --user-name="$USER_NAME"` instead of `put-role-policy`) AND deactivate the issuing `AKIA` key (branch A) — otherwise the user keeps minting new sessions.

> **Root-minted sessions: containment depends on the account type.** If the underlying principal is the **root user**, sessions minted by root via `GetSessionToken`/`GetFederationToken` cannot have their permissions changed by IAM policy ("you cannot change the permissions for the temporary security credentials that were created by calling `GetFederationToken` or `GetSessionToken` while signed in as the root user" — [Disabling permissions for temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html)), so an `aws:TokenIssueTime` Deny attached as an IAM policy has no effect on them. What does work:
> - **Member account of an AWS Organization:** an SCP applies to every principal in the account **including the root user** ([SCP effects on permissions](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)), so the organization administrator can attach an SCP with the same `aws:TokenIssueTime` `DateLessThan` Deny to that account — the AWS guidance for `GetSessionToken`/`GetFederationToken` sessions names an SCP as one of the two policy types to use ([re:Post — Managing exposed AWS access keys, step 2c](https://repost.aws/articles/ARTdf-AQfbTy--wzQmf2JOOg)).
> - **Management account:** SCPs have no effect on principals in the management account ([same page](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)), so the sessions cannot be restricted by policy. Delete the root access keys and rotate root credentials (branch E) to stop **new** sessions — deactivating or deleting a key does **not** invalidate temporary credentials it already issued ([same re:Post article, step 2](https://repost.aws/articles/ARTdf-AQfbTy--wzQmf2JOOg)) — and wait out the existing ones: sessions minted with root credentials are capped at 3,600 seconds by both `GetSessionToken` ([GetSessionToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html)) and `GetFederationToken` ([GetFederationToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html)).
> In both cases also run branch E.

### D. The subject resolves to a workload role session (instance / task / function role; `AssumedRole` whose role is a workload role)
Treat the workload as compromised: apply a session Deny keyed on `aws:userId` ([Denying access to temporary credentials by principal — `aws:userid`](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html)), and isolate the workload per GuardDuty's EC2 compromise runbook ([Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)) then snapshot for evidence ([Resolve unauthorized activity](https://repost.aws/knowledge-center/potential-account-compromise)). Snapshotting is evidence preservation the operator runs — it is **not** in `handoff.md` (handoff commands are read-only); it is containment guidance here.

### E. The subject resolves to the root user (`userIdentity.type=Root`, or an active root key in the credential report)
Separate root runbook: sign in as root, delete the root access keys, and enable/rotate root MFA ([Resolve unauthorized activity](https://repost.aws/knowledge-center/potential-account-compromise)). Root is confirmed only when a resolved event shows `userIdentity.type == Root` or the credential-report root row has an active key — never inferred from the prefix (Step 6f).

## Common lines (print always)
- If `AWSCompromisedKeyQuarantineV2` or `AWSCompromisedKeyQuarantineV3` is already attached to the principal, AWS has already detected the exposure and opened a Support case — **do not detach it until rotation completes** ([V2](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV2.html), [V3](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV3.html)). Step 1 flags whether it is attached.
- **Do not delete the user, role, or key until Step 1 evidence is captured.** Deletion is irreversible: deleting the **IAM user** removes that user's inline policies, group memberships, and attachment records, and deleting the **access key** discards it and its metadata. Deactivate (not delete) during containment so the triage can still read the evidence.
- After containment, re-run this mode with `--contained-at <timestamp>` so Step 6e can detect STILL-ACTIVE use (CloudTrail has delivery lag and the attacker may still be active).
