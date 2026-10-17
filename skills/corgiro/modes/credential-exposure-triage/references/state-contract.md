# State Contract — credential-exposure-triage

Exact JSON shapes for every file the mode writes under the Run Directory. Each step file links here instead of restating a schema; the report (Step 7) reads these files, not live API responses.

**Masking is mandatory in every file here.** No field in any schema below ever holds a full access key ID. Every `accessKeyId` is stored as a `{masked, sha256}` object — `{"masked": "AKIA****XXXX", "sha256": "<64-hex>"}` — populated in memory before the first write (see MODE.md Safety). A subject is keyed by its `sha256` fingerprint (the `<subject-fingerprint>` in paths), never by the raw key.

> The **Roster Entry** schema (`name`, `role`, `via`, `readOnlyEnforced`, `profile`, `reachable`, …) is owned by [`../../../references/credential-resolution.md`](../../../references/credential-resolution.md#roster-entry-schema-authoritative). This contract references a Roster Entry by its account ID and never restates its shape.

## `subjects.json` (Step 1a)

One entry per subject under triage. `owning_account` must be a reachable Roster Entry account ID (see above) or the subject is stopped.

```json
{
  "subjects": [
    {
      "fingerprint": "<64-hex sha256 of the raw key, or a stable id for arn/finding subjects>",
      "kind": "akia-user-key | asia-session | guardduty-finding | health-event | role-session",
      "key": { "masked": "AKIA****XXXX", "sha256": "<64-hex>" },
      "owning_account": "111111111111",
      "principal": {
        "type": "IAMUser | AssumedRole | Root | FederatedUser | Unknown",
        "name": "<iam user or role name, or null until resolved>",
        "arn": "<principal arn, or null>"
      },
      "resolved_via": "sts:GetAccessKeyInfo | iam:GetAccessKeyLastUsed | operator-supplied | guardduty:GetFindings | health:DescribeEventDetails",
      "last_used": { "date": "<iso8601 | null>", "service": "<svc | null>", "region": "<region | null>" },
      "quarantine_policy": "AWSCompromisedKeyQuarantineV2 | AWSCompromisedKeyQuarantineV3 | none | not-observable",
      "status": "resolved | unresolved | account-outside-roster | degraded-view-only",
      "derived_from": "<parent subject fingerprint, or null if operator-supplied>",
      "notes": "<free text, agent-authored, never attacker data>"
    }
  ]
}
```

## `target-plan.json` (Step 2, targeted path) / `discovery-plan.json` (Step 1b, discovery path)

The approved execution contract. Shape follows the shared plan gate in [`../../../references/sweep-plan-coverage.md`](../../../references/sweep-plan-coverage.md); this is its persisted form for this mode.

```json
{
  "mode": "targeted | discovery",
  "approved_at": "<iso8601>",
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
    }
  ],
  "caps": { "max_hops": 2, "max_sessions": 20, "max_derived_subjects": 10, "call_budget": 200, "max_parallel": 4 },
  "estimate_calls": { "lower_bound": 71, "with_pagination": 119 },
  "expansions": []
}
```

`expansions[]` is appended **only** by a Step 5 expansion gate, each element recording the batch of same-depth pivot values approved, the designated field they came from, the regex they matched, and the hop depth. Nothing outside `accounts` / `regions_by_account` is ever added.

## `signals.json` (Step 3)

```json
{
  "per_account": {
    "111111111111": {
      "guardduty": {
        "coverage": "detector-present | no-detector | not-permitted",
        "findings": [
          { "id": "<finding id>", "type": "<finding type string>", "severity": 8.0,
            "resource_access_key": { "masked": "AKIA****XXXX", "sha256": "<64-hex>" },
            "first_seen": "<iso8601>", "last_seen": "<iso8601>",
            "actor_ip": "<ip | null>", "api": "<api | null>", "region": "us-east-1" }
        ]
      },
      "health": {
        "coverage": "subscribed | subscription-required | not-permitted",
        "events": [ { "arn": "<health event arn>", "eventTypeCode": "<code>", "statusCode": "<code>", "startTime": "<iso8601>" } ]
      },
      "credential_report": { "collected": true, "stale_hint": "<freshness note>", "path": "evidence/.../credential-report.csv" }
    }
  }
}
```

`severity` here is GuardDuty's own numeric Severity reported verbatim as AWS data — it is **never** mapped to Risk Tier (CONTEXT.md: "severity" is reserved for AWS Health). `health.eventTypeCode` is matched client-side against `CREDENTIALS` (Step 3); codes are discovered at run time, never hardcoded.

## `timeline/<subject-fingerprint>/<region>-pN.json` (Step 4)

One file per subject per region per CloudTrail page (`-p1`, `-p2`, …), so one manual `NextToken` loop iteration = one counted call.

```json
{
  "subject": "<fingerprint>",
  "region": "us-east-1",
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
      "errorMessage": "<msg | null, sanitized>",
      "readOnly": false,
      "userIdentity": { "type": "IAMUser | AssumedRole | Root | ...", "accessKeyId": { "masked": "AKIA****XXXX", "sha256": "<64-hex>" }, "arn": "<arn>" },
      "requestParameters": { "<sanitized subset>": "..." },
      "responseElements": { "<sanitized subset; STS creds & CreateAccessKey only>": "..." },
      "outcome": "succeeded | attempted"
    }
  ]
}
```

`responseElements` is retained only for STS (`AssumeRole`/`GetFederationToken`/`GetSessionToken`) and `CreateAccessKey`, and any `accessKeyId` inside it is masked like every other. `outcome` is derived client-side from `errorCode` presence in the parsed `CloudTrailEvent` JSON.

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
      "watchlist_principals": ["<iam name created by CreateUser/CreateRole/CreateLoginProfile>"]
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
      "subject": "<fingerprint>",
      "account": "111111111111",
      "region": "us-east-1",
      "bucket": "Discovery | InitialAccess | CredentialAccess | Persistence | PrivilegeEscalation | DefenseEvasion | Exfiltration | Impact | ResourceAbuse",
      "event": { "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey", "eventId": "<uuid>", "eventTime": "<iso8601>" },
      "outcome": "succeeded | attempted",
      "confidence": "confirmed | observed-attempt | inferred | not-observable | partial",
      "lifecycle": { "resource_id": "<id>", "state": "created-still-live | created-then-deleted | unknown", "follow_up_event": "<eventName | null>" },
      "containment_defeating": false,
      "notes": "<agent-authored>"
    }
  ],
  "lockout": [
    { "target_principal": "<iam name, not the subject>", "via_event": "PutUserPolicy", "deny_found": true, "current_state": "<login profile / policy / key status>", "reversal": "<guidance>" }
  ],
  "ip_ua_index": [
    { "sourceIPAddress": "<ip>", "userAgents": ["<ua>"], "principals": ["<fingerprint or arn>"], "accounts": ["111111111111"] }
  ],
  "still_active": [
    { "subject": "<fingerprint>", "latest_event_time": "<iso8601>", "last_used_time": "<iso8601 | null>", "after_contained_at": true }
  ],
  "root_detected": { "present": false, "evidence": "userIdentity.type=Root | credential-report root key active | none" }
}
```

`bucket` values are assigned only on an exact `(eventSource, eventName)` match in [`event-catalog.md`](event-catalog.md); an unmatched `readOnly=true` event is generic `Discovery`. `confidence` and `outcome` are set per event. `containment_defeating: true` marks the Critical events in Step 6g.

## `completeness.json` (Step 6)

The honest coverage record that feeds the report's Methodology and every coverage statement.

```json
{
  "coverage": {
    "accounts": { "full": ["111111111111"], "partial": [ { "account": "222222222222", "reason": "call budget exhausted" } ], "unreachable": [], "errored": [] },
    "regions_queried_by_account": { "111111111111": ["us-east-1", "us-west-2"] },
    "window": { "since": "<iso8601>", "until": "<iso8601>", "clipped_to_90d": false },
    "earliest_event_returned": "<iso8601 | null>",
    "caps_hit": ["max_hops", "call_budget:222222222222"],
    "data_event_blind_spots": ["s3:GetObject", "lambda:Invoke", "dynamodb item ops"],
    "signals_unavailable": ["guardduty (view-only permission set)"],
    "call_counts": { "by_account": { "111111111111": 83 }, "total": 141 }
  }
}
```

`earliest_event_returned` bounds any coverage claim: CloudTrail pages are newest-first, so report coverage by the earliest event returned, never as a full-window scan when a page cap was hit.

## `handoff-manifest.json` (Step 7)

Declares what a later `--import <dir>` is allowed to contain. Its schema and the `--import` validation rules live in [`step-7-report-handoff.md`](step-7-report-handoff.md); this file is the contract an import is checked against (run ID, task ID, key fingerprint, account, Region, resource, format, command-template hash).
