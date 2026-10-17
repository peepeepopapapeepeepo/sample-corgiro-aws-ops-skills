# Step 3 — Collect Exposure Signals (GuardDuty + Health)

**Inputs:** `target-plan.json` (approved accounts/regions); `subjects.json`.

**Allowed calls** (all read-only), dispatched on the account's Roster Entry `via` per [`../../../references/credential-resolution.md`](../../../references/credential-resolution.md). Run up to `max_parallel` accounts concurrently (clamp 10); back off on `ThrottlingException`.

## GuardDuty — dual Access Mode path

### `cross-account-role` (delegated admin; delegation is **regional**; enumerate members)
From the delegated-admin account, **per region**: the delegated admin's own `list-detectors` does **not** list member detectors, so enumerate members explicitly. Validate each returned detector ID against `\A[0-9a-f]{32}\z` and each finding ID against `\A[0-9a-f]{32,64}\z` **immediately before use** (regex-dialect note in MODE.md); options are equals-joined:
```
aws guardduty list-detectors --region=<region> --no-paginate                            # the admin's own detector
aws guardduty list-members --detector-id=<validated admin detector id> --region=<region> --no-paginate
```
Then query findings. Build the `--finding-criteria` JSON **programmatically** from the raw key (do not paste the key into a single-quoted string, where `$COMPROMISED_ACCESS_KEY_ID_N` would not expand); validate the key against `\A(AKIA\|ASIA)[0-9A-Z]{16}\z` first:
```
CRIT="$(printf '{"Criterion":{"resource.accessKeyDetails.accessKeyId":{"Eq":["%s"]}}}' "$COMPROMISED_ACCESS_KEY_ID_N")"
aws guardduty list-findings  --detector-id=<validated detector id> --region=<region> --no-paginate --finding-criteria="$CRIT"
aws guardduty get-findings   --detector-id=<validated detector id> --region=<region> --no-paginate --finding-ids=<validated ids>   # ≤ 50 ids per call — batch
```
- `FindingCriteria` filters on `resource.accessKeyDetails.accessKeyId` (also `.userName`, `.principalId`). Source: [list-findings](https://docs.aws.amazon.com/cli/latest/reference/guardduty/list-findings.html), [FindingCriteria property](https://docs.aws.amazon.com/cdk/api/v2/docs/@aws-cdk_cfn-property-mixins.aws_guardduty.CfnFilterPropsMixin.FindingCriteriaProperty.html). The resource type for IAM findings is `AccessKey` ([compromised-creds](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)).
- `get-findings --finding-ids` accepts at most **50 ids per call** ([get-findings](https://docs.aws.amazon.com/cli/latest/reference/guardduty/get-findings.html)) — batch the ids from `list-findings`.
- **Which account's detector?** The delegated admin can query member findings through the admin detector when auto-enable/association is in place; where `list-members` shows a member not associated, record its coverage as `not-permitted` for that account/region rather than assuming silence. The delegated-admin account is read from `crossAccount.delegatedAdminAccountId` (documented in [`../../../references/cross-account-defaults.md`](../../../references/cross-account-defaults.md)); if it is unset, ask the operator once or fall back to the per-account path below.
- **No type filter** — keep every finding type. GuardDuty `Severity` is reported verbatim as AWS data and is **never** mapped to Risk Tier (CONTEXT.md).
- The key value is read from `$COMPROMISED_ACCESS_KEY_ID_N`; it is never written to `signals.json` (mask there) or to any log/debug file.

**Discovery path (no key):** there is no `accessKeyId` to filter on, so select AccessKey-type findings by **resource type** client-side — keep findings whose `resource.resourceType == "AccessKey"` (and, for ranking, the IAM compromised-credential finding types) from an unfiltered `list-findings`/`get-findings`. Do not invent a server-side criterion for "AccessKey-type".

### `identity-center-direct` (per account, direct)
Per Roster Entry: `guardduty list-detectors --region=<region> --no-paginate` per region, then `list-findings`/`get-findings` as above (same ID validation) using the per-account SSO profile. GuardDuty across many accounts × regions is expensive here (≈ `accounts × regions × ~2-3` calls → 2,000+ over 50×20); require named accounts/regions or a separate high-cost approval recorded in the Step 2 gate.

### Missing detector
A region with no detector → record `by_region.<region>.coverage: "no-detector"` and a finding "no GuardDuty detection coverage in account X region R" (Informational + recommendation). Coverage is tracked **per region** (a detector in us-east-1 does not cover ap-southeast-1). Never treat absence as "no activity".

## Health — credential-exposure events
- `cross-account-role`: `aws health describe-events-for-organization --region=us-east-1` (entitled) ([ref](https://docs.aws.amazon.com/cli/latest/reference/health/describe-events-for-organization.html)); else per account `describe-events`.
- `identity-center-direct`: per account `aws health describe-events --region=us-east-1`; skip on `SubscriptionRequiredException` (as [`health-event-analysis`](../../health-event-analysis/MODE.md)).
- Discover credential codes at run time: `describe-event-types` **unfiltered**, paginated, match `eventTypeCode` client-side on `CREDENTIALS` ([describe-event-types](https://docs.aws.amazon.com/cli/latest/reference/health/describe-event-types.html)). Never hardcode `AWS_RISK_CREDENTIALS_*` or pass a `RISK` service filter.

## Credential report (for root detection and key hygiene)
Collect the IAM credential report once per in-scope account (`aws iam generate-credential-report` then `aws iam get-credential-report`, as in Step 1b Signal 2 and [`iam-security-review`](../../iam-security-review/MODE.md)); write it to `signals/<account>/credential-report.csv` (it contains **no** access key IDs, nothing to mask). The `<root_account>` row feeds Step 6f root detection (an active root key), so this runs on the **targeted** path too, not only discovery. `generate-credential-report` is asynchronous: poll `get-credential-report` until `COMPLETE` with short backoff, bounded — at most a few polls per account, counted against `call_budget`/`global_call_budget`; if still `STARTED` after the bound, record `credential_report.collected: false` and continue. Skipped under `ViewOnlyAccess` (not granted).

## ViewOnlyAccess degradation (Path A)
`ViewOnlyAccess` grants neither GuardDuty nor Health reads (MODE.md Prerequisites); when the permission set is `ViewOnlyAccess`, skip this step, record `signals_unavailable` in `completeness.json`, and continue to Step 4. This is documented degradation, not an error.

**Hard stops:** all calls `--no-paginate` with manual `NextToken`. **Budget (both counters, pre-call):** every GuardDuty/Health/credential-report request decrements both `call_budget` (its account) and `global_call_budget` before the call; stop the account at the per-account cap (`partial — call budget exhausted`) and the whole run before a call that would exceed `global_call_budget` (`partial — global call budget exhausted`, recorded in `completeness.json`). Nothing runs outside `target-plan.json`.

**Output:** `signals.json` per [`state-contract.md`](state-contract.md).
