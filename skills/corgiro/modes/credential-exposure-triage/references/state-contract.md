# State Contract — credential-exposure-triage

Exact JSON shapes for every file the mode writes under the Run Directory. Each step file links here instead of restating a schema; the report (Step 7) reads these files, not live API responses.

**Masking is mandatory in every file here.** No field in any schema below ever holds a full access key ID. Every `accessKeyId` is stored as a `{masked, sha256}` object — `{"masked": "AKIA****XXXX", "sha256": "<64-hex>"}` — populated in memory before the first write by **sanitize-write** (below). A subject is keyed by its `sha256` fingerprint (the `<subject-fingerprint>` in paths), never by the raw key.

> The **Roster Entry** schema (`name`, `role`, `via`, `readOnlyEnforced`, `profile`, `reachable`, …) is owned by [`../../../references/credential-resolution.md`](../../../references/credential-resolution.md#roster-entry-schema-authoritative). This contract references a Roster Entry by its account ID and never restates its shape.

## Named procedures (single source of truth)

Two procedures recur across the steps. They are defined once here; every step says "apply **sanitize-write**" or "**charge** both counters" and links back, rather than respelling them.

### sanitize-write

How any object becomes a file. The only key forms ever persisted or displayed are the SHA-256 fingerprint and the masked `AKIA****XXXX` (first 4 + last 4).

1. **Populate the in-memory key map first.** While parsing each **successful** STS (`AssumeRole`/`GetFederationToken`/`GetSessionToken`) or `CreateAccessKey` response, validate the raw returned ID (`re.fullmatch` body `ASIA[0-9A-Z]{16}` or `AKIA[0-9A-Z]{16}`) and insert it into the process-local map keyed by its `sha256` — before the value is masked. Step 5 then receives each hop/derived key by fingerprint, reading the raw value from this map, never from a persisted file.
2. **Walk the parsed value tree** (not the serialized text): a field whose entire value is an access key ID becomes `{masked, sha256}`; an access key ID appearing as a **substring** of a larger string (`roleSessionName`, an ARN, `errorMessage`) becomes the masked string `AKIA****XXXX` in place, its fingerprint recorded separately.
3. **Keep only the allowlisted fields; drop the secret-bearing keys.** From the `responseElements` retained for an STS or `CreateAccessKey` response, keep only `credentials.accessKeyId` (masked), `credentials.expiration`, `assumedRoleUser.arn`, `accessKey.accessKeyId` (masked), and `accessKey.userName`/`status`/`createDate`. Drop the exact JSON keys `sessionToken` and `secretAccessKey` (CloudTrail responses, case-sensitive — this leaves `GetSessionToken` the event name untouched) and `Credentials`/`SecretAccessKey`/`SessionToken` (PascalCase CLI-import output). For an `ssm.amazonaws.com / SendCommand` event, keep only `requestParameters.documentName`, `requestParameters.instanceIds`, and `responseElements.command.commandId`, and drop `requestParameters.parameters` (AWS warns plaintext Systems Manager parameters are logged to CloudTrail and readable by anyone with log access; for `AWS-RunShellScript`, `parameters` is the script text itself — [Run Command](https://docs.aws.amazon.com/systems-manager/latest/userguide/running-commands.html)).
4. **Serialize, then scan the bytes** for `(AKIA|ASIA)[0-9A-Z]{16}`, and **write atomically only when that pre-write scan is clean**. A field that still carries `sessionToken`/`secretAccessKey`/`Credentials`/`SecretAccessKey`/`SessionToken` by exact name fails the write closed.
5. **Post-write scan (backstop).** Scan the written file once more for the same regex, ignoring the single authored doc example `AKIAIOSFODNN7EXAMPLE`; on a hit, delete the file and stop the run with an error. The pre-write scan is the guarantee; this catches a defect in it.

A **full guardrail** sits under this procedure: a full access key ID is persisted or displayed only as `{masked, sha256}` / `AKIA****XXXX`, never raw.

### Regex dialect

Every identifier regex in this mode is written as an **unanchored body for Python `re.fullmatch`** — e.g. `(AKIA|ASIA)[0-9A-Z]{16}` — which matches the whole string with no trailing-newline surprise. PCRE/Ruby/Java users wrap the same body in `\A…\z`; `^…$` is wrong (in those engines it can match up to an embedded newline). Character classes are **ASCII only**: `[A-Za-z0-9_]`, never `\w` (many engines widen `\w` to Unicode, so `adminé` would pass). A value that fails its regex is never substituted or passed to a call.

### charge

How every AWS call is budgeted. **Before each AWS request** — including the pre-gate resolution calls — decrement `global_call_budget` (run-wide) and the `call_budget` of the **account whose session issues the call**: the operator base account for `get-caller-identity` and `sts get-access-key-info` (which run from an arbitrary granting or the operator base session), the owning account for every owning-account read. One argv is one request; one manual `NextToken`/`Marker` page is one request. **Each charge also increments `completeness.coverage.call_counts.by_operation["<service>:<Operation>"]`** (e.g. `cloudtrail:LookupEvents`, `iam:GetInstanceProfile`) so the ledger records exactly which APIs were issued — Step 7 Methodology lists APIs from this map and nowhere else. Issue the call only when both counters stay within budget: at the per-account cap stop that account and mark it `partial — call budget exhausted`; at the global cap stop the whole run, mark every not-yet-finished account `partial — global call budget exhausted`, and record `caps_hit: ["global_call_budget"]` in `completeness.json`. A hop or derived-subject sweep queued by Step 5 is charged **once, by Step 4** when Step 4 runs it — Step 5 never also charges it.

## `subjects.json` (Step 1a)

One entry per subject under triage. `owning_account` must be a reachable Roster Entry account ID (see above) or the subject is stopped.

```json
{
  "subjects": [
    {
      "fingerprint": "<64-hex sha256 of the raw key, or a stable id for arn/finding/role-session subjects>",
      "kind": "akia-user-key | asia-session | guardduty-finding | health-event | role-session",
      "key": "<object { masked, sha256 } | null — null for role-session, candidate-rejected, and not-observable subjects>",
      "key_status": "valid | candidate-rejected | not-observable",
      "key_status_after_containment": "<deactivated-verified | active | expired | unknown — persisted containment state, computed read-only (see below); feeds the Step 7 containment-state column and the STILL ACTIVE banner, never re-typed in the report>",
      "owning_account": "111111111111",
      "principal": {
        "type": "IAMUser | AssumedRole | Root | FederatedUser | Unknown",
        "name": "<iam user or role name, or null until resolved>",
        "arn": "<principal arn, or null>"
      },
      "role_arn": "<role-session subjects only: the validated IAM role ARN (operator-supplied `role_arn`); null for every other kind>",
      "session_name": "<role-session subjects only: the validated `session_name` parameter; null for every other kind>",
      "resolved_via": ["<one or more of: sts:GetAccessKeyInfo, iam:GetAccessKeyLastUsed, operator-supplied, guardduty:GetFindings, health:DescribeAffectedEntities, or 'derived:<eventName>' for a derived subject>"],
      "last_used": { "date": "<iso8601 | null | 'not-observable'>", "service": "<svc | null>", "region": "<region | null>" },
      "quarantine_policy": "AWSCompromisedKeyQuarantineV2 | AWSCompromisedKeyQuarantineV3 | none | not-observable",
      "status": "resolved | unresolved | unresolved-account | account-outside-roster | degraded-view-only",
      "derived_from": "<parent subject fingerprint, or null if operator-supplied>",
      "discovered_at_depth": "<0 for operator/finding/health subjects; the hop depth at which a derived subject was created>",
      "notes": "<free text, agent-authored, never attacker data>"
    }
  ]
}
```

**`key` is nullable; `key_status` gates fan-out.** `key` is `null` whenever `key_status` is `candidate-rejected` (a Health `entityValue` or finding value that did not match `re.fullmatch` body `(AKIA|ASIA)[0-9A-Z]{16}`) or `not-observable` (role-session subject, or no key available). Only a subject with `key_status: valid` may drive the key-based targeted Step 3/4/5 fan-out; a non-`valid` **access-key** subject is reported and the mode forbids its fan-out until the operator supplies a valid `access_key_id`. **One exemption (authoritative here as in MODE.md "Key validity gate"):** a subject with `kind: role-session`, non-null `role_arn` and `session_name`, and `key_status: not-observable` **is allowed to run Step 4 only**, by the role-session `Username` lookups (its `target-plan.json` lookup has `lookup_attribute: Username`; it runs two attempts — value source `subject.session_name`, then `subject.principal.name` (the role name) as a fallback, each filtered client-side on the role); it runs no Step 3 signal collection and no Step 5 expansion. Zero kept events from both attempts is `not-observable`, never "no activity".

**`key_status_after_containment` is computed read-only, with a fixed precedence.** When `target-plan.json.contained_at` is set, Step 6e/Step 7 derive this field per subject from state, never from operator assertion, using the precedence **`active` > `expired` > `deactivated-verified` > `unknown`** (the first that applies wins):
- **`active`** — a primary-search event by this subject (key fingerprint, or role ARN + session name) is later than `contained_at`, **or** `iam list-access-keys` reports the key `Active`, **or** the STS session's `responseElements.credentials.expiration` is still in the future. (A post-containment event wins even over an expired session, so the banner and the column agree.)
- **`expired`** — a temporary `ASIA` session whose captured `expiration` is in the past **and** no post-`contained_at` event exists. Still note that any trusting principal can re-mint it (Step 0 branch B trust-policy read).
- **`deactivated-verified`** — `iam list-access-keys --user-name=<validated name>` reports the key `Inactive` (or the `AWSRevokeOlderSessions` Deny is attached, for a role), with no post-`contained_at` event.
- **`unknown`** — the status call was denied or not run, or no `contained_at` was supplied.
A subject the STILL ACTIVE banner (Step 6e) flags is `active` here by construction.

**Derived subjects are appended here too.** Step 5 queues each attacker-created key as a derived subject; it writes the hop/derived tree to `sessions.json` **and** appends a matching entry to `subjects.json` (with `derived_from` set to the parent fingerprint and `discovered_at_depth` set to the hop depth), so every subject the mode traced has one `subjects.json` record. Step 4 then runs a timeline for it like any other subject. A derived subject's `resolved_via` is **`"derived:<eventName>"`** (e.g. `derived:CreateAccessKey`), never `operator-supplied` — it was discovered from a traced event, not handed in by the operator.



## `target-plan.json` (Step 2, targeted path) / `discovery-plan.json` (Step 1b, discovery path)

The approved execution contract. Shape follows the shared plan gate in [`../../../references/sweep-plan-coverage.md`](../../../references/sweep-plan-coverage.md); this is its persisted form for this mode.

```json
{
  "mode": "targeted | discovery",
  "access_mode": "cross-account-role | identity-center-direct",
  "approved_at": "<iso8601>",
  "contained_at": "<iso8601 | null — the operator's --contained-at parameter, persisted so Step 6e STILL-ACTIVE and the Step 7 containment-state column are computed from state, never re-typed>",
  "window": { "since": "<iso8601>", "until": "<iso8601>", "clipped_to_90d": false },
  "accounts": ["111111111111", "222222222222"],
  "regions_by_account": { "111111111111": ["us-east-1", "us-west-2"] },
  "read_only_enforced_false": ["222222222222"],
  "subjects": ["<fingerprint>", "..."],
  "lookups": [
    {
      "step": "4",
      "service": "cloudtrail",
      "command": "lookup-events",
      "lookup_attribute": "AccessKeyId",
      "value_source": "subject.key (masked in plan display)",
      "scope": "per-account per-region, us-east-1 first"
    },
    {
      "step": "4",
      "service": "cloudtrail",
      "command": "lookup-events",
      "lookup_attribute": "Username",
      "value_source": "role-session subjects only (no AccessKeyId fingerprint): attempt 1 subject.session_name, attempt 2 subject.principal.name (role name) as a fallback — both filtered client-side on the role; never a single value",
      "scope": "owning account only, per enabled region, us-east-1 first; these are the subject's PRIMARY lookups (pages tagged search: primary). Attempt-1 events are kept when userIdentity.sessionContext.sessionIssuer.arn == subject.role_arn; attempt-2 events are kept additionally only when userIdentity.arn's last /-segment == subject.session_name. Zero kept events from both attempts = not-observable, never 'no activity'"
    }
  ],
  "caps": { "max_hops": 2, "max_sessions": 20, "max_derived_subjects": 10, "call_budget": 200, "global_call_budget": 2000, "max_parallel": 4 },
  "estimate_calls": { "lower_bound": 71, "with_pagination": 119 },
  "expansions": []
}
```

`expansions[]` is appended **only** by a Step 5 expansion gate. Each element has the shape:

```json
{ "depth": 1, "kind": "hop | derived-subject | instance-session",
  "values": [ { "masked": "ASIA****XXXX", "sha256": "<64-hex>" } ],
  "designated_field": "responseElements.credentials.accessKeyId",
  "regex": "ASIA[0-9A-Z]{16}",
  "accounts": ["222222222222"], "approved_at": "<iso8601>" }
```

Nothing outside the already-approved `accounts` / `regions_by_account` is ever added — an expansion adds only lookup **values**, never a new account, region, or command.

## `signals.json` (Step 3)

```json
{
  "per_account": {
    "111111111111": {
      "guardduty": {
        "by_region": {
          "us-east-1": { "coverage": "detector-present | no-detector | not-permitted | not-associated",
            "findings": [
              { "id": "<finding id>", "type": "<finding type string>", "severity": 8.0,
                "resource_type": "AccessKey",
                "resource_access_key": { "masked": "AKIA****XXXX", "sha256": "<64-hex>" },
                "first_seen": "<iso8601>", "last_seen": "<iso8601>",
                "actor_ip": "<ip | null>", "api": "<api | null>" } ] },
          "ap-southeast-1": { "coverage": "no-detector", "findings": [] }
        }
      },
      "health": {
        "coverage": "subscribed | subscription-required | not-permitted",
        "events": [ { "arn": "<health event arn>", "eventTypeCode": "<code>", "statusCode": "<code>", "startTime": "<iso8601>",
                      "candidate_key": "<object { masked, sha256 } | null — null when candidate_key_status is candidate-rejected or not-observable>",
                      "candidate_key_status": "valid | candidate-rejected | not-observable" } ]
      },
      "credential_report": { "collected": true, "stale_hint": "<freshness note>", "path": "signals/<account>/credential-report.csv" }
    }
  }
}
```

`severity` here is GuardDuty's own numeric Severity reported verbatim as AWS data — it is **never** mapped to Risk Tier (CONTEXT.md: "severity" is reserved for AWS Health). `health.eventTypeCode` is matched client-side against `CREDENTIALS` (Step 3); codes are discovered at run time, never hardcoded.

## `timeline/<subject-fingerprint>/<region>[-rn|-un]-pN.json` (Step 4)

One file per subject per region per CloudTrail page (`-p1`, `-p2`, …), so one manual `NextToken` loop iteration = one counted call. The infix marks the **role** of the search that produced the page, not the attribute: none for a key subject's **primary** `AccessKeyId` lookup; for a **role-session** subject's two primary `Username` attempts, `-rsn-` (by session name) and `-rrn-` (by role name) — distinct infixes so the two independently-paginated streams never overwrite each other, both `search: "primary"`; `-rn` for the supplemental `ResourceName` search; `-un` for the supplemental `Username=<instance id>` instance-session search (Step 5). `lookup_attribute` records the attribute actually sent. Step 6 unions the `-rsn-`/`-rrn-` streams and deduplicates by `eventId`.

```json
{
  "subject": "<fingerprint>",
  "region": "us-east-1",
  "search": "primary | resourcename | username",
  "lookup_attribute": "AccessKeyId | Username | ResourceName",
  "page": 1,
  "next_token_present": true,
  "events": [
    {
      "eventId": "<uuid>",
      "eventSource": "iam.amazonaws.com",
      "eventName": "CreateAccessKey",
      "eventTime": "<iso8601>",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "<ip | aws-service>",
      "userAgent": "<ua string, sanitized before report>",
      "errorCode": "<code | null>",
      "errorMessage": "<msg | null, sanitized, value-masked>",
      "readOnly": false,
      "userIdentity": { "type": "IAMUser | AssumedRole | Root | ...", "accessKeyId": { "masked": "AKIA****XXXX", "sha256": "<64-hex>" }, "arn": "<arn>" },
      "requestParameters": { "<sanitized subset, value-masked>": "..." },
      "responseElements": {
        "note": "present ONLY for STS AssumeRole/GetFederationToken/GetSessionToken, CreateAccessKey, ssm SendCommand, and ec2 RunInstances — each with only the members shown for it",
        "credentials": { "accessKeyId": { "masked": "ASIA****XXXX", "sha256": "<64-hex>" }, "expiration": "<iso8601>" },
        "assumedRoleUser": { "arn": "<arn>" },
        "accessKey": { "accessKeyId": { "masked": "AKIA****XXXX", "sha256": "<64-hex>" }, "userName": "<name>", "status": "Active", "createDate": "<iso8601>" },
        "command": { "commandId": "<uuid — ssm.amazonaws.com/SendCommand only; the only responseElements member kept for that event>" },
        "instancesSet": { "items": [ { "instanceId": "i-0123456789abcdef0" } ] }
      },
      "outcome": "succeeded | attempted"
    }
  ]
}
```

`responseElements` is kept only for STS, `CreateAccessKey`, `ssm.amazonaws.com / SendCommand`, and `ec2.amazonaws.com / RunInstances`, and only the fields above: STS events keep `credentials.accessKeyId` (masked) / `credentials.expiration` / `assumedRoleUser.arn`; `CreateAccessKey` keeps the `accessKey` object; `SendCommand` keeps **only** `command.commandId` (the identifier Step 6b's `ssm list-commands` follow-up and the Step 7 SSM handoff task need) and nothing else from its response, while its `requestParameters` are reduced to `documentName` and `instanceIds` with `parameters` dropped before the first write (MODE.md Safety); `RunInstances` keeps **only** `instancesSet.items[].instanceId` (the IDs the Step 6b `ec2 describe-instances` lifecycle follow-up reads; an instance ID is not an access key and needs no masking). `accessKey.accessKeyId` is retained (masked) because Step 5 and the lifecycle `CreateAccessKey` row pair on it; the raw value of any hop/derived key is captured into the in-memory `sha256`→key map **before** masking (MODE.md Safety) and Step 5 reads it from there. The JSON keys named **`sessionToken` and `secretAccessKey` are dropped** (exact names, case-sensitive); if a field by either exact name survives into bytes about to be written, the write fails closed. Every key ID anywhere in the page is sanitized in memory (whole-value → `{masked, sha256}`; substring in a string → `AKIA****XXXX`) before the pre-write scan. `outcome` is derived client-side from `errorCode` presence in the parsed `CloudTrailEvent` JSON.

## `sessions.json` (Step 5)

A tree: subject → hops → derived subjects, plus instance-role session reviews.

```json
{
  "subjects": {
    "<fingerprint>": {
      "hops": [
        {
          "depth": 1,
          "via_event": { "eventName": "AssumeRole", "eventId": "<uuid>", "eventTime": "<iso8601>", "outcome": "succeeded" },
          "target_account": "222222222222",
          "in_roster": true,
          "derived_key": { "masked": "ASIA****XXXX", "sha256": "<64-hex>" },
          "assumed_role_arn": "<arn>",
          "followed": true,
          "reason_not_followed": null
        }
      ],
      "derived_subjects": [
        { "created_by_event": "CreateAccessKey", "eventId": "<uuid>", "key": { "masked": "AKIA****XXXX", "sha256": "<64-hex>" }, "same_account": "111111111111", "queued": true }
      ],
      "instance_sessions": [
        { "trigger_event": "SendCommand", "instance_id": "i-0123456789abcdef0", "username_lookup_done": true }
      ],
      "watchlist_principals": ["<iam name proven created by a successful CreateUser or CreateRole only>"]
    }
  }
}
```

`in_roster: false` means the hop target is outside the Roster — the attempt is reported, never followed. `followed: false` with a `reason_not_followed` records a cap hit (`max_hops`, `max_sessions`, `max_derived_subjects`) or a failed STS call (never recurse on a failed STS call).

## `findings.json` (Step 6)

```json
{
  "findings": [
    {
      "id": "f-001",
      "kind": "event",
      "subject": "<fingerprint>",
      "account": "111111111111",
      "region": "us-east-1",
      "bucket": "Discovery | InitialAccess | CredentialAccess | Persistence | PrivilegeEscalation | DefenseEvasion | Exfiltration | Impact | ResourceAbuse",
      "event": { "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey", "eventId": "<uuid>", "eventTime": "<iso8601>" },
      "outcome": "succeeded | attempted",
      "confidence": "confirmed | observed-attempt | inferred | not-observable | partial",
      "lifecycle": { "resource_id": "<id>", "state": "created-still-live | created-then-deleted | unknown", "follow_up_event": "<eventName | null>", "instance_profile_role": "<RunInstances only: the role name from iam get-instance-profile InstanceProfile.Roles[].RoleName, or null>" },
      "containment_defeating": false,
      "notes": "<agent-authored>"
    }
  ],
  "coverage_gaps": [
    {
      "id": "g-001",
      "kind": "coverage-gap",
      "gap_type": "no-guardduty-detector | health-subscription-required | signal3-partial | permission-degraded",
      "account": "111111111111",
      "region": "us-east-1 | null",
      "risk_tier": "Informational",
      "recommendation": "<agent-authored, e.g. enable GuardDuty in this account/region>"
    }
  ],
  "lockout": [
    { "target_principal": "<iam name, not the subject>", "via_event": "PutUserPolicy", "event_id": "<uuid — the same event>", "bucket": "Impact", "deny_found": true, "current_state": "<login profile / policy / key status>", "reversal": "<guidance>" }
  ],
  "ip_ua_index": [
    { "sourceIPAddress": "<ip>", "userAgents": ["<ua>"], "principals": ["<fingerprint or arn>"], "accounts": ["111111111111"], "actor_class": "attacker | other-actor" }
  ],
  "still_active": [
    { "subject": "<fingerprint>", "latest_event_time": "<iso8601>", "last_used_time": "<iso8601 | null>", "after_contained_at": true }
  ],
  "root_detected": { "present": false, "evidence": "userIdentity.type=Root | credential-report root key active | none" }
}
```

`bucket` values are assigned only on an exact `(eventSource, eventName)` match in [`event-catalog.md`](event-catalog.md); an unmatched `readOnly=true` event is generic `Discovery`. `confidence` and `outcome` are set per event. `containment_defeating: true` marks the Critical events in Step 6g. On the discovery path with no subject picked, `findings[]` is empty and `coverage_gaps[]` carries the detection-coverage findings. **Lockout invariant:** every `lockout[]` entry carries `bucket: "Impact"`, and the **same event in `findings[]` (matched by `event.eventId` == `lockout[].event_id`) MUST also be `bucket: "Impact"`** — a Deny-direction lockout is one classification, not `Impact` in the lockout table and `PrivilegeEscalation` in the finding/timeline (event-catalog two-row split; Step 6a direction rule).

## `discovery-result.json` (Step 1b, discovery path)

The ranked suspect table the operator picks from; also the discovery-path report's data source.

```json
{
  "ranked_suspects": [
    {
      "key": "<object { masked, sha256 } | null — null when key_status is candidate-rejected or not-observable>",
      "key_status": "valid | candidate-rejected | not-observable",
      "owner": "<iam user/role name | null>",
      "account": "111111111111",
      "signals_fired": ["signal-0-health", "signal-1-guardduty", "signal-2-credential-report", "signal-3-sample"],
      "first_seen": "<iso8601 | null>",
      "why": "<agent-authored reason>",
      "confidence": "near-certain | likely | hygiene-flag | sampled"
    }
  ],
  "all_signals_empty": false,
  "detection_coverage": ["<per-account/region coverage summary, mirrors completeness.coverage>"]
}
```

When `all_signals_empty` is `true`, the report states `no exposure signal observed; detection coverage: <list>` — never an all-clear (Risk Tier Informational, `badge--zinc`).

## `completeness.json` (Step 6)

The honest coverage record that feeds the report's Methodology and every coverage statement.

```json
{
  "coverage": {
    "accounts": { "full": ["111111111111"], "partial": [ { "account": "222222222222", "reason": "call budget exhausted" } ], "unreachable": [], "errored": [] },
    "regions_queried_by_account": { "111111111111": ["us-east-1", "us-west-2"] },
    "regions_source": "account:ListRegions | operator-supplied | config defaultRegions | fallbackRegions",
    "enabled_regions_not_queried": "<list of enabled Regions in the footprint that were not queried, or null when the enabled set is unknown (account:ListRegions not run)>",
    "window": { "since": "<iso8601>", "until": "<iso8601>", "clipped_to_90d": false },
    "earliest_event_returned": "<iso8601 | null>",
    "caps_hit": ["max_hops", "call_budget:222222222222", "global_call_budget"],
    "data_event_blind_spots": ["s3:GetObject", "lambda:Invoke", "dynamodb item ops"],
    "signals_unavailable": ["guardduty (view-only permission set)"],
    "call_counts": { "by_account": { "111111111111": 83 }, "by_operation": { "cloudtrail:LookupEvents": 61, "guardduty:GetFindings": 4, "iam:ListAccessKeys": 2, "ec2:DescribeInstances": 1, "iam:GetInstanceProfile": 1 }, "total": 141, "global_budget": 2000 }
  },
  "audit_records": [
    { "eventSource": "s3.amazonaws.com", "eventName": "PutBucketVersioning", "eventId": "<uuid>", "account": "111111111111", "note": "versioning Status=Enabled — benign config change, not a finding" }
  ]
}
```

`earliest_event_returned` bounds any coverage claim: CloudTrail pages are newest-first, so report coverage by the earliest event returned, never as a full-window scan when a page cap was hit.

## `handoff-manifest.json` (Step 7)

Declares what a later `--import <dir>` is allowed to contain. Its schema and the `--import` validation rules live in [`step-7-report-handoff.md`](step-7-report-handoff.md); this file is the contract an import is checked against (run ID, task ID, key fingerprint, account, Region, resource, format, `commands_hash`).
