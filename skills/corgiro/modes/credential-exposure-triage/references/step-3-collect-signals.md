# Step 3 — Collect Exposure Signals (GuardDuty + Health)

**Inputs:** `target-plan.json` (approved accounts/regions); `subjects.json`.

**Allowed calls** (all read-only), dispatched on the account's Roster Entry `via` per [`../../../references/credential-resolution.md`](../../../references/credential-resolution.md). Run up to `max_parallel` accounts concurrently (clamp 10); back off on `ThrottlingException`.

## GuardDuty — dual Access Mode path

### `cross-account-role` (delegated admin; delegation is **regional**)
Query from the delegated-admin account **per region**:
```
aws guardduty list-detectors --region <region> --no-paginate
aws guardduty list-findings --detector-id <id> --region <region> --no-paginate \
  --finding-criteria '{"Criterion":{"resource.accessKeyDetails.accessKeyId":{"Eq":["<RAW KEY — from $COMPROMISED_ACCESS_KEY_ID, never logged>"]}}}'
aws guardduty get-findings --detector-id <id> --finding-ids <ids> --region <region> --no-paginate
```
- `FindingCriteria` filters on `resource.accessKeyDetails.accessKeyId` (also `.userName`, `.principalId`). Source: [list-findings](https://docs.aws.amazon.com/cli/latest/reference/guardduty/list-findings.html), [FindingCriteria property](https://docs.aws.amazon.com/cdk/api/v2/docs/@aws-cdk_cfn-property-mixins.aws_guardduty.CfnFilterPropsMixin.FindingCriteriaProperty.html). The resource type for IAM findings is `AccessKey` ([compromised-creds](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)).
- **No type filter** — keep every finding type. GuardDuty `Severity` is reported verbatim as AWS data and is **never** mapped to Risk Tier (CONTEXT.md).
- The key value passed to `--finding-criteria` is read from `$COMPROMISED_ACCESS_KEY_ID`; it is never written to `signals.json` (mask there) or to any log/debug file.

### `identity-center-direct` (per account, direct)
Per Roster Entry: `guardduty list-detectors` per region, then `list-findings`/`get-findings` as above using the per-account SSO profile. GuardDuty across many accounts × regions is expensive here (≈ `accounts × regions × ~2-3` calls → 2,000+ over 50×20); require named accounts/regions or a separate high-cost approval recorded in the Step 2 gate.

### Missing detector
A region/account with no detector → record `coverage: "no-detector"` and a finding "no GuardDuty detection coverage in account X" (Informational + recommendation). Never treat absence as "no activity".

## Health — credential-exposure events
- `cross-account-role`: `aws health describe-events-for-organization --region us-east-1` (entitled) ([ref](https://docs.aws.amazon.com/cli/latest/reference/health/describe-events-for-organization.html)); else per account `describe-events`.
- `identity-center-direct`: per account `aws health describe-events --region us-east-1`; skip on `SubscriptionRequiredException` (as [`health-event-analysis`](../../health-event-analysis/MODE.md)).
- Discover credential codes at run time: `describe-event-types` **unfiltered**, paginated, match `eventTypeCode` client-side on `CREDENTIALS` ([describe-event-types](https://docs.aws.amazon.com/cli/latest/reference/health/describe-event-types.html)). Never hardcode `AWS_RISK_CREDENTIALS_*` or pass a `RISK` service filter.

## ViewOnlyAccess degradation (Path A)
`ViewOnlyAccess` grants neither GuardDuty nor Health reads (MODE.md Prerequisites); when the permission set is `ViewOnlyAccess`, skip this step, record `signals_unavailable` in `completeness.json`, and continue to Step 4. This is documented degradation, not an error.

**Hard stops:** all calls `--no-paginate` with manual `NextToken`, counted against `call_budget`; nothing outside `target-plan.json`.

**Output:** `signals.json` per [`state-contract.md`](state-contract.md).
