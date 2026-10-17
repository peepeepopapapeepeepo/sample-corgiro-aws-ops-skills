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
- For a Health event, validate the supplied `health_event_arn` with `re.fullmatch` body `arn:aws[a-z-]*:health:[a-z0-9-]*:[0-9]*:event/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+` (the account field is **optional** on Health event ARNs — it may be empty — so the account segment is `[0-9]*`) before use, then make **two** calls: `aws health describe-event-details --event-arns=<arn> --region=us-east-1` returns the event **description** ([DescribeEventDetails](https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeEventDetails.html)); then `aws health describe-affected-entities --filter='{"eventArns":["<arn>"]}' --region=us-east-1` returns the affected entities, whose `entities[].entityValue` the API documents only as "the ID of the affected entity" ([DescribeAffectedEntities](https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeAffectedEntities.html) → [AffectedEntity](https://docs.aws.amazon.com/health/latest/APIReference/API_AffectedEntity.html)). Treat `entityValue` as a **candidate** only: accept it as the subject key (`key_status: valid`) **iff** it matches `re.fullmatch` body `(AKIA|ASIA)[0-9A-Z]{16}`; otherwise set `key: null` with `key_status: candidate-rejected` (non-key value) or `not-observable` (no entity) and require an operator-supplied `access_key_id` before fan-out.
  - **Health is a global service with its endpoint in `us-east-1`; on a `us-east-1` impairment it fails over to `us-east-2`.** The resolve calls target `us-east-1`; if they fail, retry against `us-east-2` ([Health API multi-Region](https://docs.aws.amazon.com/health/latest/ug/health-api.html)).

These are read-only and count against the budget (per MODE.md "Budget accounting"); they are the one exception to "print before any call".

## Conditional containment branches (print the generic banner, then the branch Step 1 resolves)

Identity is unknown before Step 1, and the key **prefix never selects a branch** — an `AKIA` can be an IAM-user key or a root key, and an `ASIA` can be a role session, a federation/session-token session, or a workload-role session. So:
- **Before Step 1 resolves** (and for the no-subject discovery path, which has no key yet): print a **generic banner** listing all identity branches A-E with the one-line condition under which each applies ("if the key resolves to an IAM-user key …", "… to a role session …", etc.), and instruct the operator to wait for the resolved branch unless they already know the identity. Branch F is **additive** — it applies alongside whichever identity branch resolves, whenever the subject launched instances with an instance profile (Step 6), not as an alternative identity.
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

> **Derived (attacker-created) keys have no `$COMPROMISED_ACCESS_KEY_ID_N` — resolve the full ID by `sha256`, never by a suffix.** The operator never supplied a derived key, so there is no env var and no 4-character `AKIA****XXXX` suffix match (two keys can share a suffix, and a suffix match can deactivate the wrong key). Instead, print a read-only lookup that lists the owning user's keys, then match the returned **full** ID whose SHA-256 equals the subject fingerprint, deactivating that matched value:
> ```
> #!/bin/bash
> # not executed by Corgiro — save and run under your own authority
> set -eu
> # 1) list the owner's keys (read-only); <DERIVED_KEY_OWNER_AFTER_STEP_1> and <FINGERPRINT> are Corgiro-filled, validated
> OWNER='<DERIVED_KEY_OWNER_AFTER_STEP_1>'
> FINGERPRINT='<SUBJECT_FINGERPRINT_64HEX>'
> MATCH=''            # initialize empty so no stale value from the environment can leak into the mutation
> COUNT=0
> # 2) pick the ID whose sha256 equals the subject fingerprint (no suffix match):
> for KID in $(aws iam list-access-keys --user-name="$OWNER" --no-paginate --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
>   if [ "$(printf %s "$KID" | shasum -a 256 | cut -d' ' -f1)" = "$FINGERPRINT" ]; then
>     MATCH="$KID"; COUNT=$((COUNT + 1))
>   fi
> done     # python one-liner equivalent: hashlib.sha256(kid.encode()).hexdigest() == fingerprint
> # 3) deactivate ONLY when exactly one key matched the fingerprint; otherwise stop before any mutation:
> if [ "$COUNT" -ne 1 ]; then
>   echo "expected exactly 1 key matching the fingerprint, found $COUNT; refusing to deactivate" >&2; exit 1
> fi
> aws iam update-access-key --access-key-id="$MATCH" --status=Inactive --user-name="$OWNER"
> ```
> `<SUBJECT_FINGERPRINT_64HEX>` is the derived subject's `sha256` fingerprint from `subjects.json` (not a key value); `<DERIVED_KEY_OWNER_AFTER_STEP_1>` is the validated owner name. `MATCH` is initialized empty inside the script and matches are counted, so a stale inherited value cannot be mutated and zero-or-multiple matches stop before `update-access-key`. The full key ID lives only in the operator's shell variable for the single deactivate call and is never persisted by Corgiro.

### B. The subject resolves to a role session (`ASIA…`, `userIdentity.type=AssumedRole` from `AssumeRole`)
Revoke in-flight sessions by attaching the `AWSRevokeOlderSessions` inline policy — an `aws:TokenIssueTime` `DateLessThan` Deny — to the role. This requires `iam:PutRolePolicy` and **affects every session of that role issued before the revoke cutoff, not just the attacker's** ([Revoke IAM role temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)). The block below has exactly two values Corgiro fills, both as **quoted literals on the first two lines** (never left as unset variables): the revoke cutoff and the role name. The **revoke cutoff is the report-generation time plus 30 seconds** (a freshly captured `now + 30 s` at the moment Corgiro produces this runbook — **not** `contained_at`, and **not** `window.until`) — a session the attacker re-mints during collection must still be caught, and AWS's console revoke denies sessions issued up to "approximately 30 seconds into the future" to cover policy-propagation delay ([revoke-sessions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)). The captured timestamp is validated against `ISO8601_TS` and **must be later than the newest observed attacker session's issue time**; if the operator runs the script hours later, regenerate so the cutoff is still fresh. Corgiro generates the cutoff as an ISO-8601 literal (UTC, `Z` suffix), validates it against the `ISO8601_TS` body in [`step-7-report-handoff.md`](step-7-report-handoff.md) → "Per-type substitution regexes" before writing it, and fills the role name only after Step 1 resolved it and it matched the IAM-name body `[A-Za-z0-9][A-Za-z0-9_+=.@-]{0,63}`. **The source example below carries the placeholder `<GENERATED_AT_PLUS_30S>`, never a fixed literal; when Corgiro writes `containment.md` it substitutes a freshly captured report-generation-time-plus-30-seconds literal that validates against `ISO8601_TS` and is later than the newest observed attacker session's issue time, and it refuses to write a runnable script (emits prose + the revoke-sessions doc link instead) if it cannot generate such a value.** Until Step 1 resolves, the role-name line shows the placeholder `<ROLE_NAME_AFTER_STEP_1>` and the block must not be run. **Run the block as a saved script, not an interactive paste:** save it as `revoke.sh` and run `bash revoke.sh`. A `: "${VAR:?msg}"` guard aborts a *script* on an empty value but, pasted line by line into an interactive shell, only fails that one line and lets the rest run; and an *unresolved placeholder* like `<ROLE_NAME_AFTER_STEP_1>` is non-empty, so the empty-check alone would pass it through. The block therefore (a) is meant to be run as a script, (b) **chains every step with `&&`** so any failure stops the chain before `put-role-policy`, and (c) **rejects any value still containing `<`** (an unfilled placeholder) in addition to the empty check. The policy body is a fixed template written to a `mktemp` file created under `umask 077` and passed by `file://`:
```
#!/bin/bash
# revoke.sh — not executed by Corgiro; save and run as `bash revoke.sh` under your own authority
set -eu
REVOKE_CUTOFF_ISO8601='<GENERATED_AT_PLUS_30S>'   # Corgiro substitutes a FRESH ISO-8601 literal (report-generation time + 30 s) when it writes containment.md
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

> **Read the role's trust policy — an expired or revoked session can be re-minted.** Revoking or expiring a session stops that session, but **any principal the role trusts can assume it again**. Corgiro reads the trust policy read-only in-Mode (`aws iam get-role --role-name=<validated role name>` → `Role.AssumeRolePolicyDocument`; `iam:GetRole` is in `ReadOnlyAccess`) and reports who the role trusts, so the operator can tighten the trust policy (remove the attacker-reachable principal) or deny the role entirely rather than only revoking the one session. This is why an `expired` containment state (Step 7) still warrants action.

### C. The subject resolves to `ASIA…` from `GetSessionToken` / `GetFederationToken`
These are minted by an underlying IAM user. Apply an `aws:TokenIssueTime` Deny on **the user** (same policy body and same cutoff rule as branch B — **run time + 30 s**, not `contained_at` — attached with `iam put-user-policy --user-name="$USER_NAME"` instead of `put-role-policy`) AND deactivate the issuing `AKIA` key (branch A) — otherwise the user keeps minting new sessions.

> **Root-minted sessions: containment depends on the account type.** If the underlying principal is the **root user**, sessions minted by root via `GetSessionToken`/`GetFederationToken` cannot have their permissions changed by IAM policy ("you cannot change the permissions for the temporary security credentials that were created by calling `GetFederationToken` or `GetSessionToken` while signed in as the root user" — [Disabling permissions for temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html)), so an `aws:TokenIssueTime` Deny attached as an IAM policy has no effect on them. What does work:
> - **Member account of an AWS Organization:** an SCP applies to every principal in the account **including the root user** ([SCP effects on permissions](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)), so the organization administrator can attach an SCP with the same `aws:TokenIssueTime` `DateLessThan` Deny to that account — the AWS guidance for `GetSessionToken`/`GetFederationToken` sessions names an SCP as one of the two policy types to use ([re:Post — Managing exposed AWS access keys, step 2c](https://repost.aws/articles/ARTdf-AQfbTy--wzQmf2JOOg)).
> - **Management account:** SCPs have no effect on principals in the management account ([same page](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)), so the sessions cannot be restricted by policy. Delete the root access keys and rotate root credentials (branch E) to stop **new** sessions — deactivating or deleting a key does **not** invalidate temporary credentials it already issued ([same re:Post article, step 2](https://repost.aws/articles/ARTdf-AQfbTy--wzQmf2JOOg)) — and wait out the existing ones: sessions minted with root credentials are capped at 3,600 seconds by both `GetSessionToken` ([GetSessionToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html)) and `GetFederationToken` ([GetFederationToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html)).
> In both cases also run branch E.

### D. The subject resolves to a workload role session (instance / task / function role; `AssumedRole` whose role is a workload role)
Treat the workload as compromised: apply a session Deny keyed on `aws:userId` ([Denying access to temporary credentials by principal — `aws:userid`](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html)), and isolate the workload per GuardDuty's EC2 compromise runbook ([Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)) then snapshot for evidence ([Resolve unauthorized activity](https://repost.aws/knowledge-center/potential-account-compromise)). Snapshotting is evidence preservation the operator runs — it is **not** in `handoff.md` (handoff commands are read-only); it is containment guidance here.

### E. The subject resolves to the root user (`userIdentity.type=Root`, or an active root key in the credential report)
Separate root runbook: sign in as root, delete the root access keys, and enable/rotate root MFA ([Resolve unauthorized activity](https://repost.aws/knowledge-center/potential-account-compromise)). Root is confirmed only when a resolved event shows `userIdentity.type == Root` or the credential-report root row has an active key — never inferred from the prefix (Step 6f).

### F. A successful `RunInstances` (any subject that launched instances)
When a **succeeded `RunInstances`** is in the timeline (Step 6; the created instance IDs are in `responseElements.instancesSet.items[].instanceId`), the attacker has a live instance. Contain it — and, when it carries a role, contain that role too.

**Resolve the instance-profile role in-mode (read-only) so the revoke script is filled, not "edit the template".** `ec2 describe-instances` returns only the instance **profile** (`IamInstanceProfile.Arn`/`Id`), not the role ([describe-instances](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html)); the role name is obtained with `aws iam get-instance-profile --instance-profile-name=<validated profile name>` → `InstanceProfile.Roles[].RoleName` (the profile name is the text after the final `/` of the `IamInstanceProfile.Arn` when only the ARN is present — [IAM identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html)) (`Roles` is required; `iam:GetInstanceProfile` is in `ReadOnlyAccess` — [get-instance-profile](https://docs.aws.amazon.com/cli/latest/reference/iam/get-instance-profile.html)). This is wired into **Step 6** as a second charged follow-up on the `RunInstances` lifecycle row (event-catalog), which persists the resolved role name in `findings[].lifecycle`; Corgiro then **regenerates `containment.md` after Step 6** so branch F's `revoke.sh` carries the filled role name. If the role cannot be resolved read-only, the branch-B script keeps `<ROLE_NAME_AFTER_STEP_1>` unfilled (its `<`-rejecting guard stops the run).

**Containment order — isolate first, then evidence snapshot, then revoke the role's sessions (fail-fast).** Isolate the instance first (GuardDuty's compromised-EC2 remediation supports isolation with a dedicated security group) so live attacker access is cut, then preserve evidence, then revoke; the isolate-before-revoke order follows from the revoke-sessions semantics cited below. Save and run as a script:
```
#!/bin/bash
# not executed by Corgiro — save and run under your own authority
set -eu
INSTANCE_ID='<validated i-…>'            # Corgiro-filled from responseElements.instancesSet.items[].instanceId
VOLUME_ID='<validated vol-… of the instance>'
QUARANTINE_SG='<operator-supplied quarantine security group id>'
# 1) ISOLATE the instance first — attach an isolation security group that allows no traffic.
#    modify-instance-attribute --groups errors if the instance has more than one ENI; for a
#    multi-ENI instance set the group per ENI with modify-network-interface-attribute instead.
aws ec2 modify-instance-attribute --instance-id="$INSTANCE_ID" --groups="$QUARANTINE_SG" &&
# NOTE: changing security groups does NOT terminate existing tracked connections, so a live
#   attacker session can persist — add a Network ACL deny on the subnet to cut live sessions.
# 2) evidence-snapshot BEFORE revoking; fail-fast so a failed snapshot stops here:
aws ec2 create-snapshot --volume-id="$VOLUME_ID" --description="corgiro-evidence-$INSTANCE_ID" || { echo "snapshot failed — preserve evidence first" >&2; exit 1; }
# 3) revoke sessions on the instance-profile ROLE (resolved above) — run the branch-B revoke.sh:
bash revoke.sh
```
([GuardDuty — Remediating a compromised EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html); [modify-instance-attribute errors with >1 ENI](https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-instance-attribute.html); [security-group connection tracking — existing connections survive a group change](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html).) **The role revoke hits every instance using that role**, and it does **not** stop a still-running instance from receiving fresh role credentials from the instance metadata service after the cutoff ("if the user assumes the role after you revoked the permissions, then the deny policy does not apply" — [revoke-sessions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)); that is why the instance is isolated in step 1 before the revoke. **If the activity cannot be stopped, GuardDuty recommends an isolation security group and ultimately terminating the instance** — note that **stopping discards RAM and instance-store data** (an instance-store-backed instance cannot even be stopped — [stop/start effects](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-ec2-instance-stop-start-works.html)), and **terminating permanently loses instance-store data and deletes every EBS volume flagged delete-on-termination, by default the root volume** ([terminating instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html)), so snapshot first and isolate rather than stop or terminate when evidence matters. **A launched instance with no instance profile** is isolated the same way (step 1) and snapshotted (step 2); there is no role, so skip step 3. These are mutating operator guidance (not run by Corgiro); the `describe-instances` / `get-instance-profile` reads that surface the IDs and the role are the read-only Step 6b follow-ups.

## Common lines (print always)
- **Containment order, and who runs this when admins are locked out.** Contain **every** subject — including every derived (attacker-created) subject and any instance-role session — and verify each is `deactivated-verified`/`expired` **before** restoring any locked-out legitimate principal; restoring a locked-out admin while attacker access is still live lets the attacker re-apply the Deny. If the attacker locked out the IAM administrators (6c), the operator runs this runbook as the AWS account **root user** or a pre-provisioned **break-glass role** — locked-out IAM admins cannot ([AWS root-user best practices — reserve root for tasks that require it, including recovering locked-out access](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html)).
- **If a trail was stopped or deleted, restart logging.** When a `StopLogging` or `DeleteTrail` event **succeeded** for the subject (DefenseEvasion, Step 6), re-enable the trail: `aws cloudtrail start-logging --name=<trail name or ARN>`, then confirm with `aws cloudtrail get-trail-status --name=<trail>` — `IsLogging: true` means logging resumed; `StopLoggingTime` shows when it was off ([get-trail-status returns IsLogging / StopLoggingTime, per Region](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html)). (`get-trail-status` is read-only, in `ReadOnlyAccess`; `start-logging` is mutating operator guidance here, not run by Corgiro.)
- If `AWSCompromisedKeyQuarantineV2` or `AWSCompromisedKeyQuarantineV3` is already attached to the principal, AWS has already detected the exposure and opened a Support case — **do not detach it until rotation completes** ([V2](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV2.html), [V3](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV3.html)). Step 1 flags whether it is attached.
- **Do not delete the user, role, or key until Step 1 evidence is captured.** Deletion is irreversible: deleting the **IAM user** removes that user's inline policies, group memberships, and attachment records, and deleting the **access key** discards it and its metadata. Deactivate (not delete) during containment so the triage can still read the evidence.
- After containment, re-run this mode with `--contained-at <timestamp>` so Step 6e can detect STILL-ACTIVE use (CloudTrail has delivery lag and the attacker may still be active).
