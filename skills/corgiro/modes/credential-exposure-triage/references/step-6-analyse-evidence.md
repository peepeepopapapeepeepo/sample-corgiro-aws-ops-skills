# Step 6 — Analyse Evidence (client-side; no new AWS calls except budgeted follow-ups)

Classify the fetched evidence entirely client-side over the persisted `timeline/*`, `signals.json`, and `sessions.json`. The only AWS calls here are the budgeted lifecycle follow-ups in 6b (static table, ID-only substitution). Outputs `findings.json` + `completeness.json` (schemas in [`state-contract.md`](state-contract.md)).

**Classification precedence (verbatim guardrail):** the exact event-catalog tuple takes precedence over `readOnly`; classify unmatched `readOnly=true` events as generic Discovery only.

## 6a — Bucket classification
Assign a bucket **only** on an exact `(eventSource, eventName)` match in [`event-catalog.md`](event-catalog.md) — **no prefix matching**. Buckets follow GuardDuty's tactic taxonomy: `Discovery | InitialAccess | CredentialAccess | Persistence | PrivilegeEscalation | DefenseEvasion | Exfiltration | Impact | ResourceAbuse`. An event matched to no tuple but carrying `readOnly=true` is generic `Discovery`. Each event also gets `outcome` (succeeded | attempted) and `confidence` (confirmed | observed-attempt | inferred | not-observable | partial).

## 6b — Lifecycle pairing (budgeted read-only follow-ups)
Pair each **create** event with its **delete** event using the explicit `(source, create eventName, delete pair eventName, pair key)` rows in the static lifecycle table in [`event-catalog.md`](event-catalog.md) — matching on the row's pair-key field, never by prefix or wildcard — to decide "created, still live" vs "created then deleted (staging)". Within `call_budget`, confirm live state with that same table's read-only follow-up argv, substituting only the resource ID validated by the row's regex column. Examples the table encodes (each cited there): `kms describe-key`, `ec2 describe-snapshots --owner-ids self` + `describe-snapshot-attribute --attribute createVolumePermission`, `ec2 describe-iam-instance-profile-associations`, `ssm list-commands` (metadata only — never `get-command-invocation` output), `lambda list-functions` + `get-policy` (`GetFunction`/`GetFunctionConfiguration` are denied by the member role), `logs describe-log-streams` (timestamps only — `FilterLogEvents`/`GetLogEvents` denied), `cloudformation describe-stacks` (StackSet enumeration needs delegated-admin authority; else not observable), `iam get-user`/`get-role`/`get-policy`, `cloudtrail get-event-selectors` (does any trail log S3 data events?). **Every lifecycle row MUST define source, create event name, delete pair event name, success predicate, resource-ID JSON path, pair key, account/Region source, and follow-up argv template; missing fields prohibit pairing and follow-up.**

> `cloudformation list-stack-instances` needs StackSets management / delegated-admin authority that a normal member/tooling session lacks. When unavailable, inspect local state only and mark organization StackSet health **not observable** — do not claim coverage.

> **Follow-ups never substitute a raw key.** Any follow-up that would key on an access key ID (e.g. confirming a created key is live) uses `iam list-access-keys --user-name <validated name>` and matches the target by `sha256` against the masked key — a masked `AKIA****XXXX` cannot be passed to `--access-key-id` and no raw value is persisted to substitute (MODE.md Safety). Raw hop/derived keys needed for a *Step 4* timeline come from the in-memory key map, never from a persisted file.

## 6c — Lockout analysis
Identify IAM events whose **target principal is a legitimate principal** — i.e. **not** the subject's own principal and **not** an attacker-created principal on `sessions.json.watchlist_principals` (the watchlist holds attacker-created identities, so excluding it leaves only pre-existing legitimate ones). For each such `PutUserPolicy` / `PutRolePolicy` / `AttachUserPolicy` / `AttachRolePolicy` / `DetachUserPolicy` / `UpdateAssumeRolePolicy` / `DeleteLoginProfile` / `UpdateAccessKey(Inactive)` event:
- For an **inline**-policy event (`PutUserPolicy`/`PutRolePolicy`), parse the event's `requestParameters.policyDocument` for `"Effect":"Deny"`.
- For a **managed**-policy `Attach*` event there is no inline document in the event; record the attached `policyArn` and, within budget, resolve it with the lockout follow-up table rows below (`iam get-policy` + `iam get-policy-version`).
- Confirm current state within budget using the lockout follow-up rows (login profile, inline/attached policies, trust policy, key status). The principal name is validated `^[\w+=,.@-]{1,64}$` before any follow-up.

Produce a table of locked-out legitimate principals with reversal **guidance**. Reversal text is mutating guidance, so it goes in `containment.md` (not run by Corgiro) and never interpolates an attacker-controlled free-text field — only the regex-validated principal name. Attacker-targeted StackSet execution roles are flagged by name match against the member role's StackSet-managed naming (`StackSet-*` / the operator's configured prefix); Corgiro's own role is StackSet-managed, so its appearance as a target is called out.

**Lockout follow-up rows** (read-only; ID-only substitution; same gate and budget as 6b):

| target eventName | read-only follow-up (argv) | ID JSON path | ID regex |
|---|---|---|---|
| PutUserPolicy / AttachUserPolicy / DetachUserPolicy | `iam list-attached-user-policies --user-name <ID>` then `iam list-user-policies --user-name <ID>` | `requestParameters.userName` | `^[\w+=,.@-]{1,64}$` |
| AttachUserPolicy / AttachRolePolicy (managed) | `iam get-policy --policy-arn <ID>` then `iam get-policy-version --policy-arn <ID> --version-id <v from get-policy>` | `requestParameters.policyArn` | `^arn:aws[\w-]*:iam::(aws\|[0-9]{12}):policy/[\w+=,.@/-]{1,128}$` |
| PutRolePolicy / UpdateAssumeRolePolicy | `iam get-role --role-name <ID>` | `requestParameters.roleName` | `^[\w+=,.@-]{1,64}$` |
| DeleteLoginProfile | `iam get-login-profile --user-name <ID>` | `requestParameters.userName` | `^[\w+=,.@-]{1,64}$` |
| UpdateAccessKey (targeting another principal) | `iam list-access-keys --user-name <ID>` (match the affected key by sha256) | `requestParameters.userName` | `^[\w+=,.@-]{1,64}$` |

## 6d — IP / user-agent pivot
Build a client-side index of `sourceIPAddress` / `userAgent` across **all** fetched events (all subjects): which principals were seen from each IP, for operator attribution. There is **no** server-side IP lookup attribute in `lookup-events` ([LookupAttribute](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupAttribute.html) lists no IP key) — say so and point to CloudTrail Lake / Athena (Step 7 handoff). Sanitize every `userAgent`/IP string before it reaches the report.

## 6e — STILL ACTIVE
Per subject, STILL ACTIVE counts **only** events whose `userIdentity.accessKeyId` sha256 **equals the subject fingerprint** — i.e. actions the subject key itself performed, drawn from primary-search pages only (`search: "primary"`), never from supplemental `ResourceName`/`Username` pages (those are actions done *to* the principal, including the operator's own post-containment `UpdateAccessKey(Inactive)`, and must not raise a false positive). If that latest subject-actor event time, or `get-access-key-last-used` (≤4 h, 15-min-ish granularity — [get_access_key_last_used](https://docs.aws.amazon.com/botocore/latest/reference/services/iam/client/get_access_key_last_used.html)), is later than `--contained-at`, raise `STILL ACTIVE — containment incomplete` at the top of the terminal and report. **Route to the root runbook only from an event for this subject with `userIdentity.type=Root`. A post-containment event confirms STILL ACTIVE; last-used data alone means possible activity.**

## 6f — Root detection + quarantine
Root is confirmed only by `userIdentity.type == Root` on a resolved event, or a credential-report root row with an active key (Step 0 branch E). Record whether `AWSCompromisedKeyQuarantineV2`/`V3` is attached (from Step 1a).

## 6g — Containment-defeating events (Critical)
Mark `containment_defeating: true` for: `UpdateAccessKey` reactivating a key; `DetachUserPolicy`/`DetachRolePolicy` targeting `AWSCompromisedKeyQuarantine*`; `UpdateAccountPasswordPolicy`/`DeleteAccountPasswordPolicy`. These are Critical regardless of other activity.

**Hard stops:** no bucket without an exact tuple; data events (S3 object reads, Lambda `Invoke`, DynamoDB item ops) are `not-observable`, never "none"; record `data_event_blind_spots` and `signals_unavailable` in `completeness.json`.

**Output:** `findings.json` + `completeness.json`.
