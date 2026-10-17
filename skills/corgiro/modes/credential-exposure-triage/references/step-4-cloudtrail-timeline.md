# Step 4 — CloudTrail Timeline (per subject, per region)

**Inputs:** `target-plan.json`; `subjects.json`.

**Allowed call** (read-only), per subject per enabled region, **us-east-1 first** (IAM and global-endpoint STS events are recorded as global service events in us-east-1; Regional STS endpoint calls log in their own Region — [global service events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html), [IAM/STS CloudTrail](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)). Pass the raw key via a **file or JSON** form of `--lookup-attributes` (never string-interpolated shorthand), reading the value from the subject's `$COMPROMISED_ACCESS_KEY_ID_N` (operator subject) or the in-memory key map (hop/derived subject):
```
aws cloudtrail lookup-events \
  --lookup-attributes "$(printf '[{"AttributeKey":"AccessKeyId","AttributeValue":"%s"}]' "$COMPROMISED_ACCESS_KEY_ID_1")" \
  --start-time <since> --end-time <until> \
  --region <region> --no-paginate
```
Using the JSON form (or `file://`) means the value is never pasted into shorthand `Key=…,Value=…` where a `,` or `=` in the value could retarget the lookup. Then loop manually on the returned `NextToken`, passing it back as `--next-token=<token>` on the next `--no-paginate` request (one page = one counted call; the CLI's `--starting-token` cannot be combined with `--no-paginate` — see [`../../../references/cross-account-defaults.md`](../../../references/cross-account-defaults.md) → "Which pagination options to use").

**Account scope of the primary lookup.** A long-term `AKIA` key's events exist only in its **owning account**, so its primary `AccessKeyId` lookup runs **only in that owning account**, regardless of the `accounts` scope. Hop `ASIA` keys and derived `AKIA` keys are looked up in **their own** accounts. The broader `accounts` scope and the supplemental searches below are the only things that fan across other plan accounts.

**Role-session subject path (`role_arn` + `session_name`).** A role-session subject has **no** access key to look up by `AccessKeyId`. CloudTrail's `Username` lookup attribute matches "a user name or role name of the requester" ([Event.Username](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Event.html)) — the docs do **not** promise that an `AssumedRole` event is retrievable by its session name, and Event history may index it by the **role name** instead. So run **two attempts** in the subject's owning account, both filtered client-side on the role, and combine their results:

- **Attempt 1 — by session name:**
```
aws cloudtrail lookup-events \
  --lookup-attributes "$(printf '[{"AttributeKey":"Username","AttributeValue":"%s"}]' "$VALIDATED_SESSION_NAME")" \
  --start-time <since> --end-time <until> --region <region> --no-paginate
```
`$VALIDATED_SESSION_NAME` is `subjects.json.session_name` (validated in Step 1a with `re.fullmatch` body `[A-Za-z0-9][A-Za-z0-9_+=.@-]{1,63}`) — **not** `principal.name`, which holds the role. Keep only events whose `userIdentity.sessionContext.sessionIssuer.arn == subjects.json.role_arn`.
- **Attempt 2 — by role name (fallback, always run):**
```
aws cloudtrail lookup-events \
  --lookup-attributes "$(printf '[{"AttributeKey":"Username","AttributeValue":"%s"}]' "$VALIDATED_ROLE_NAME")" \
  --start-time <since> --end-time <until> --region <region> --no-paginate
```
`$VALIDATED_ROLE_NAME` is the role name from `subjects.json.principal.name`. From these results keep only events whose `userIdentity.sessionContext.sessionIssuer.arn == subjects.json.role_arn` **and** whose `userIdentity.arn` **last segment** (the text after the final `/` of the assumed-role ARN `…:assumed-role/<role>/<session>`) **equals `subjects.json.session_name`** — so the fallback cannot leak another session of the same role.

Each attempt is a separate counted lookup (both decrement the budget). For `AssumedRole` events CloudTrail records the issuing role at `userIdentity.sessionContext.sessionIssuer.arn` ([userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)). These are this subject's **primary** lookups (the only ones it has), so their kept events are tagged `search: "primary"` with `lookup_attribute: "Username"` and written as `<region>-pN.json` — Step 6e's STILL-ACTIVE test reads primary pages. **Zero kept events from both attempts is recorded as `not-observable`, never "no activity"** (Event history may simply not index this session under either value). (`search: "username"` / `-un-` files are reserved for the supplemental instance-session search in Step 5.)

**Facts (cited):**
- Valid `LookupAttributeKey` values: `EventId | EventName | ReadOnly | Username | ResourceType | ResourceName | EventSource | AccessKeyId` ([LookupAttribute](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupAttribute.html)).
- Event history covers the **last 90 days**, **50 events per page** (max 50), and lookup is rate-limited to **two requests per second, per account, per Region** ([LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)). Respect the 2 req/s cap with backoff. Set `clipped_to_90d: true` when `since <= now − 90d` (the window reaches the edge of Event history); clamp `since` to `now − 90d`.
- CloudTrail Insights lookups accept only `EventId`, `EventName`, or `EventSource` as attributes ([LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)), so if Insights is enabled it is queried by `EventName`, **never** by `AccessKeyId`.

**Record per event** (into the page schema in [`state-contract.md`](state-contract.md)): `eventSource`, `eventName`, `eventTime`, `awsRegion`, `sourceIPAddress`, `userAgent`, `errorCode`/`errorMessage`, sanitized `requestParameters`, `userIdentity` (with its `accessKeyId` masked), and — **only** for STS (`AssumeRole`/`GetFederationToken`/`GetSessionToken`), `CreateAccessKey`, (`command.commandId` only) `ssm.amazonaws.com / SendCommand`, and (`instancesSet.items[].instanceId` only) `ec2.amazonaws.com / RunInstances` — a **minimal** `responseElements` subset: `credentials.accessKeyId` (masked), `credentials.expiration`, `assumedRoleUser.arn`, `accessKey.accessKeyId` (masked — Step 5 and the lifecycle `CreateAccessKey` row pair on this), `accessKey.userName`/`status`/`createDate`, and the `RunInstances` instance IDs (so the Step 6b `ec2 describe-instances` lifecycle follow-up has its resource ID). The field drops this implies — SSM `SendCommand` `requestParameters.parameters`, the `sessionToken`/`secretAccessKey` keys, and populating the key map before masking — are part of **sanitize-write** ([`state-contract.md`](state-contract.md) → Named procedures); Step 5 then reads hop/derived keys from the map by fingerprint. Parse `readOnly`, `errorCode`, and `userIdentity` from the embedded `CloudTrailEvent` JSON client-side, and separate succeeded from attempted by `errorCode` presence.

**Tag each page with the search that produced it.** The page schema's `search` field records the **role** of the search: the subject's primary lookup (`"primary"` — `AccessKeyId` for key subjects, `Username=<session name>` for a role-session subject), the supplemental `ResourceName` search (`"resourcename"`), or the supplemental `Username=<instance id>` instance-session search (`"username"`, Step 5); `lookup_attribute` records the attribute actually sent. Step 6e's STILL-ACTIVE test reads primary pages only and matches the subject's own identity (key fingerprint, or role ARN + session name), so supplemental-search events (which are events done *to* the principal, often by the operator or others) never falsely raise STILL ACTIVE. File names encode the search too: `<region>-pN.json` for primary, `<region>-rn-pN.json` for ResourceName, `<region>-un-pN.json` for the instance-session Username search.

**The gated supplemental `ResourceName` search (runs here, after the Step 2 gate — not in Step 1):**
After the Step 2 gate, and only with the principal name validated by `re.fullmatch` body `[A-Za-z0-9][A-Za-z0-9_+=.@-]{0,63}` (first char alphanumeric, ASCII, no comma, no newline), run a supplemental lookup for events done **to** the principal (policy attaches, trust changes), using the JSON/file form of `--lookup-attributes` so the validated name is never pasted into shorthand:
```
aws cloudtrail lookup-events \
  --lookup-attributes "$(printf '[{"AttributeKey":"ResourceName","AttributeValue":"%s"}]' "$VALIDATED_PRINCIPAL_NAME")" \
  --start-time <since> --end-time <until> --region <region> --no-paginate
```
Tag these pages `search: "resourcename"` (file `<region>-rn-pN.json`). The `ResourceName` search and the Step 5 instance-session `Username=<instance id>` search are **supplemental**: zero results never prove no activity, and their events never count toward STILL ACTIVE (Step 6e reads primary pages only). The role-session subject's own `Username=<session name>` lookup above is **not** supplemental — it is that subject's primary lookup.

**Masking (sanitize-write).** Apply **sanitize-write** ([`state-contract.md`](state-contract.md) → Named procedures) to every page before it is written: the map is populated from the raw STS/`CreateAccessKey` IDs first, the parsed tree is masked (`roleSessionName`, ARNs, `errorMessage` substrings become `AKIA****XXXX`), the secret keys are dropped, the bytes are scanned, and the page is written atomically only when clean. The raw key is only ever the `--lookup-attributes` value, sourced from `$COMPROMISED_ACCESS_KEY_ID_N` or the in-memory map.

**Budget (charge).** **Charge** both counters before each `lookup-events` request, including each manual `NextToken` page ([`state-contract.md`](state-contract.md) → Named procedures).

**Hard stops:** `--no-paginate` + manual token; both budget counters enforced pre-call (above); CloudTrail pages are newest-first, so record `earliest_event_returned` for the coverage statement.

**Dual Access Mode:** `cloudtrail:LookupEvents` is granted by `CorgiroReadOnlyRole`, `SecurityAudit`, and `ViewOnlyAccess`, so this step runs on every path (it is the one signal ViewOnlyAccess retains).

**Output:** `timeline/<subject-fingerprint>/<region>-pN.json` pages.
