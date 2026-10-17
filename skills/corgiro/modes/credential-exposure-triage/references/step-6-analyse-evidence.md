# Step 6 — Analyse Evidence (client-side; no new AWS calls except budgeted follow-ups)

Classify the fetched evidence entirely client-side over the persisted `timeline/*`, `signals.json`, and `sessions.json`. The only AWS calls here are the budgeted lifecycle follow-ups in 6b (static table, ID-only substitution). Outputs `findings.json` + `completeness.json` (schemas in [`state-contract.md`](state-contract.md)).

**Classification precedence (verbatim guardrail):** the exact event-catalog tuple takes precedence over `readOnly`; classify unmatched `readOnly=true` events as generic Discovery only.

## 6a — Bucket classification
Assign a bucket **only** on an exact `(eventSource, eventName)` match in [`event-catalog.md`](event-catalog.md) — **no prefix matching**. Buckets follow GuardDuty's tactic taxonomy: `Discovery | InitialAccess | CredentialAccess | Persistence | PrivilegeEscalation | DefenseEvasion | Exfiltration | Impact | ResourceAbuse`. An event matched to no tuple but carrying `readOnly=true` is generic `Discovery`. Each event also gets `outcome` (succeeded | attempted) and `confidence` (confirmed | observed-attempt | inferred | not-observable | partial).

## 6b — Lifecycle pairing (budgeted read-only follow-ups)
Pair each **create** event with its **delete** event using the explicit `(source, create eventName, delete pair eventName, pair key)` rows in the static lifecycle table in [`event-catalog.md`](event-catalog.md) — matching on the row's pair-key field, never by prefix or wildcard — to decide "created, still live" vs "created then deleted (staging)". Within `call_budget`, confirm live state with that same table's read-only follow-up argv, substituting only the resource ID validated by the row's regex column. Examples the table encodes (each cited there): `kms describe-key`, `ec2 describe-snapshots --owner-ids self` + `describe-snapshot-attribute --attribute createVolumePermission`, `ec2 describe-iam-instance-profile-associations`, `ssm list-commands` (metadata only — never `get-command-invocation` output), `lambda list-functions` + `get-policy` (`GetFunction`/`GetFunctionConfiguration` are denied by the member role), `logs describe-log-streams` (timestamps only — `FilterLogEvents`/`GetLogEvents` denied), `cloudformation describe-stacks` (StackSet enumeration needs delegated-admin authority; else not observable), `iam get-user`/`get-role`/`get-policy`, `cloudtrail get-event-selectors` (does any trail log S3 data events?). **Every lifecycle row MUST define source, create event name, delete pair event name, success predicate, resource-ID JSON path, pair key, account/Region source, and follow-up argv template; missing fields prohibit pairing and follow-up.**

> `cloudformation list-stack-instances` needs StackSets management / delegated-admin authority that a normal member/tooling session lacks. When unavailable, inspect local state only and mark organization StackSet health **not observable** — do not claim coverage.

## 6c — Lockout analysis
IAM `Put`/`Attach`/`Detach`/`Update`/`Delete` events whose target is **not** the subject's principal (from `sessions.json.watchlist_principals`): parse the `policyDocument` for `Effect: Deny`, then check current state via the same static follow-up table, gate, and budget as 6b (login profile, inline/attached policies, trust policy, key status). Produce a table of locked-out legitimate principals with reversal guidance. Attacker-targeted StackSet execution roles are flagged (Corgiro's own role is StackSet-managed). The principal name is validated `^[\w+=,.@-]{1,64}$` before any follow-up.

## 6d — IP / user-agent pivot
Build a client-side index of `sourceIPAddress` / `userAgent` across **all** fetched events (all subjects): which principals were seen from each IP, for operator attribution. There is **no** server-side IP lookup attribute in `lookup-events` ([LookupAttribute](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupAttribute.html) lists no IP key) — say so and point to CloudTrail Lake / Athena (Step 7 handoff). Sanitize every `userAgent`/IP string before it reaches the report.

## 6e — STILL ACTIVE
Per subject, if the latest event time, or `get-access-key-last-used` (≤4 h, 15-min-ish granularity — [get_access_key_last_used](https://docs.aws.amazon.com/botocore/latest/reference/services/iam/client/get_access_key_last_used.html)), is later than `--contained-at`, raise `STILL ACTIVE — containment incomplete` at the top of the terminal and report. **Route to the root runbook only from an event for this subject with `userIdentity.type=Root`. A post-containment event confirms STILL ACTIVE; last-used data alone means possible activity.**

## 6f — Root detection + quarantine
Root is confirmed only by `userIdentity.type == Root` on a resolved event, or a credential-report root row with an active key (Step 0 branch E). Record whether `AWSCompromisedKeyQuarantineV2`/`V3` is attached (from Step 1a).

## 6g — Containment-defeating events (Critical)
Mark `containment_defeating: true` for: `UpdateAccessKey` reactivating a key; `DetachUserPolicy`/`DetachRolePolicy` targeting `AWSCompromisedKeyQuarantine*`; `UpdateAccountPasswordPolicy`/`DeleteAccountPasswordPolicy`. These are Critical regardless of other activity.

**Hard stops:** no bucket without an exact tuple; data events (S3 object reads, Lambda `Invoke`, DynamoDB item ops) are `not-observable`, never "none"; record `data_event_blind_spots` and `signals_unavailable` in `completeness.json`.

**Output:** `findings.json` + `completeness.json`.
