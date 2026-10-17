# Step 4 — CloudTrail Timeline (per subject, per region)

**Inputs:** `target-plan.json`; `subjects.json`.

**Allowed call** (read-only), per subject per enabled region, **us-east-1 first** (IAM events and global-endpoint STS events land in us-east-1; regional STS endpoints log per region). Pass the raw key via a **file or JSON** form of `--lookup-attributes` (never string-interpolated shorthand), reading the value from the subject's `$COMPROMISED_ACCESS_KEY_ID_N` (operator subject) or the in-memory key map (hop/derived subject):
```
aws cloudtrail lookup-events \
  --lookup-attributes "$(printf '[{"AttributeKey":"AccessKeyId","AttributeValue":"%s"}]' "$COMPROMISED_ACCESS_KEY_ID_1")" \
  --start-time <since> --end-time <until> \
  --region <region> --no-paginate
```
Using the JSON form (or `file://`) means the value is never pasted into shorthand `Key=…,Value=…` where a `,` or `=` in the value could retarget the lookup. Then loop manually on the returned `NextToken` (one page = one counted call).

**Facts (cited):**
- Valid `LookupAttributeKey` values: `EventId | EventName | ReadOnly | Username | ResourceType | ResourceName | EventSource | AccessKeyId` ([LookupAttribute](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupAttribute.html)).
- Event history covers the **last 90 days**, **50 events per page** (max 50), and lookup is rate-limited to **two requests per second, per account, per Region** ([LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)). Respect the 2 req/s cap with backoff.
- CloudTrail Insights lookups accept only `EventId`, `EventName`, or `EventSource` as attributes ([LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)), so if Insights is enabled it is queried by `EventName`, **never** by `AccessKeyId`.

**Record per event** (into the page schema in [`state-contract.md`](state-contract.md)): `eventSource`, `eventName`, `eventTime`, `awsRegion`, `sourceIPAddress`, `userAgent`, `errorCode`/`errorMessage`, sanitized `requestParameters`, `userIdentity` (with its `accessKeyId` masked), and — **only** for STS (`AssumeRole`/`GetFederationToken`/`GetSessionToken`) and `CreateAccessKey` — a **minimal** `responseElements` subset: `credentials.accessKeyId` (masked), `credentials.expiration`, `assumedRoleUser.arn`, `accessKey.accessKeyId` (masked — Step 5 and the lifecycle `CreateAccessKey` row pair on this), and `accessKey.userName`/`status`/`createDate`. **Before masking** a successful STS or `CreateAccessKey` response, populate the in-memory `sha256`→raw-key map from the raw `credentials.accessKeyId` / `accessKey.accessKeyId` (MODE.md Safety "populate the map before sanitizing"); Step 5 then reads hop/derived keys from the map by fingerprint, never from the persisted (masked) page. **Drop the JSON keys named `sessionToken` and `secretAccessKey`** (exact names, case-sensitive — not `GetSessionToken`); if a field by either exact name survives into bytes about to be written, fail closed. Parse `readOnly`, `errorCode`, and `userIdentity` from the embedded `CloudTrailEvent` JSON client-side. **Separate succeeded from attempted** by `errorCode` presence.

**Tag each page with the search that produced it.** The page schema's `search` field records whether a page came from the primary `AccessKeyId` lookup (`"primary"`), the supplemental `ResourceName` search (`"resourcename"`), or the `Username` instance search (`"username"`). Step 6e's STILL-ACTIVE test counts only events whose `userIdentity.accessKeyId` sha256 equals the subject fingerprint, so supplemental-search events (which are events done *to* the principal, often by the operator or others) never falsely raise STILL ACTIVE. File names encode the search too: `<region>-p1.json` for primary, `<region>-rn-p1.json` for ResourceName, `<region>-un-p1.json` for Username.

**The gated supplemental `ResourceName` search (runs here, after the Step 2 gate — not in Step 1):**
After the Step 2 gate, and only with the principal name validated against `\A[A-Za-z0-9][\w+=.@-]{0,63}\z` (first char alphanumeric, no comma, full-string match, no newline), run a supplemental lookup for events done **to** the principal (policy attaches, trust changes), using the JSON/file form of `--lookup-attributes` so the validated name is never pasted into shorthand:
```
aws cloudtrail lookup-events \
  --lookup-attributes "$(printf '[{"AttributeKey":"ResourceName","AttributeValue":"%s"}]' "$VALIDATED_PRINCIPAL_NAME")" \
  --start-time <since> --end-time <until> --region <region> --no-paginate
```
Tag these pages `search: "resourcename"` (file `<region>-rn-pN.json`). `ResourceName` and `Username` searches are **supplemental**: zero results never prove no activity, and their events never count toward STILL ACTIVE (Step 6e filters by actor sha256).

**Masking — type-safe in memory, then atomic write (MODE.md Safety).** Do **not** serialize then patch. Walk the parsed event/page tree: a field whose whole value is a key ID becomes `{masked, sha256}`; a key ID that is a substring of a string (`roleSessionName`, an ARN, `errorMessage`) becomes the masked string `AKIA****XXXX` in place, fingerprint recorded separately. Then serialize, scan the bytes for `(AKIA|ASIA)[0-9A-Z]{16}`, and **write atomically only if that scan is clean**. A post-write scan backstops it (delete + stop on any hit). The raw key is only ever the `--lookup-attributes` value, sourced from `$COMPROMISED_ACCESS_KEY_ID_N` or the in-memory map.

**Budget (both counters, pre-call).** Before each `lookup-events` request (including each manual `NextToken` page), decrement both `call_budget` (this account) and `global_call_budget` (run-wide). Stop the account and mark it `partial — call budget exhausted` at the per-account cap; stop the **whole run** (`partial — global call budget exhausted`, recorded in `completeness.json`) before issuing a call that would exceed the global cap.

**Hard stops:** `--no-paginate` + manual token; both budget counters enforced pre-call (above); CloudTrail pages are newest-first, so record `earliest_event_returned` for the coverage statement.

**Dual Access Mode:** `cloudtrail:LookupEvents` is granted by `CorgiroReadOnlyRole`, `SecurityAudit`, and `ViewOnlyAccess`, so this step runs on every path (it is the one signal ViewOnlyAccess retains).

**Output:** `timeline/<subject-fingerprint>/<region>-pN.json` pages.
