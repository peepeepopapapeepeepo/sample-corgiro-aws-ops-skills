# Step 4 — CloudTrail Timeline (per subject, per region)

**Inputs:** `target-plan.json`; `subjects.json`.

**Allowed call** (read-only), per subject per enabled region, **us-east-1 first** (IAM events and global-endpoint STS events land in us-east-1; regional STS endpoints log per region):
```
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$COMPROMISED_ACCESS_KEY_ID" \
  --start-time <since> --end-time <until> \
  --region <region> --no-paginate
```
Then loop manually on the returned `NextToken` (one page = one counted call).

**Facts (cited):**
- Valid `LookupAttributeKey` values: `EventId | EventName | ReadOnly | Username | ResourceType | ResourceName | EventSource | AccessKeyId` ([LookupAttribute](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupAttribute.html)).
- Event history covers the **last 90 days**, **50 events per page** (max 50), and lookup is rate-limited to **two requests per second, per account, per Region** ([LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)). Respect the 2 req/s cap with backoff.
- CloudTrail Insights lookups accept only `EventId`, `EventName`, or `EventSource` as attributes ([LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)), so if Insights is enabled it is queried by `EventName`, **never** by `AccessKeyId`.

**Record per event** (into `timeline/<subject-fingerprint>/<region>-pN.json`, schema in [`state-contract.md`](state-contract.md)): `eventSource`, `eventName`, `eventTime`, `awsRegion`, `sourceIPAddress`, `userAgent`, `errorCode`/`errorMessage`, sanitized `requestParameters`, and `responseElements` **only** for STS and `CreateAccessKey`. Parse `readOnly`, `errorCode`, and `userIdentity` from the embedded `CloudTrailEvent` JSON client-side. **Separate succeeded from attempted** by `errorCode` presence.

**The gated supplemental `ResourceName` search (moved here from Step 1, guardian item 2):**
After the Step 2 gate, and only with the principal name validated against `^[\w+=,.@-]{1,64}$`, run a supplemental lookup for events done **to** the principal (policy attaches, trust changes):
```
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<validated principal name> \
  --start-time <since> --end-time <until> --region <region> --no-paginate
```
`ResourceName` and `Username` searches are **supplemental**: zero results never prove no activity (MODE.md Safety).

**Masking:** before writing any page, replace every `accessKeyId` (in `userIdentity`, `responseElements`, anywhere) with `{masked, sha256}`. The raw key is only ever the `--lookup-attributes` value, read from `$COMPROMISED_ACCESS_KEY_ID`.

**Hard stops:** `--no-paginate` + manual token; stop a region at `call_budget` and mark it `partial`; CloudTrail pages are newest-first, so record `earliest_event_returned` for the coverage statement.

**Dual Access Mode:** `cloudtrail:LookupEvents` is granted by `CorgiroReadOnlyRole`, `SecurityAudit`, and `ViewOnlyAccess`, so this step runs on every path (it is the one signal ViewOnlyAccess retains).

**Output:** `timeline/<subject-fingerprint>/<region>-pN.json` pages.
