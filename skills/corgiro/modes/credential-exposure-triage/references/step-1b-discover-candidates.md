# Step 1b — Discover Candidates (discovery path, no subject supplied)

When no subject is given, rank suspect credentials from exposure signals, then let the operator pick subjects for the targeted path. **Gate first:** write `discovery-plan.json` (accounts, regions, which signals, call estimate) and present the plan gate per [`../../../references/sweep-plan-coverage.md`](../../../references/sweep-plan-coverage.md) **before any fan-out**.

**Inputs:** Roster; `expected_regions` (authoritative footprint; default config `defaultRegions`); `accounts`/`regions` if the operator scoped them.

**Signals, cheapest and most certain first:**

### Signal 0 — AWS Health credential-exposure events (always; near-certain; names the key)
- `aws health describe-event-types --region us-east-1` **unfiltered**, paginated; match `eventTypeCode` **client-side** against `CREDENTIALS`. Never hardcode `AWS_RISK_CREDENTIALS_*` and never pass a `RISK` service filter — the code set changes. Source: [describe-event-types](https://docs.aws.amazon.com/cli/latest/reference/health/describe-event-types.html) (unfiltered returns all event types).
- Then pull matching events: `describe-events-for-organization` (entitled org) ([ref](https://docs.aws.amazon.com/cli/latest/reference/health/describe-events-for-organization.html)) or per-account `describe-events`. The affected key is **not** returned by `describe-event-details` (description only — [DescribeEventDetails](https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeEventDetails.html)); get it from `describe-affected-entities --filter '{"eventArns":["<arn>"]}'`, whose `entities[].entityValue` carries the affected access key ([DescribeAffectedEntities](https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeAffectedEntities.html)); validate it against `^(AKIA|ASIA)[0-9A-Z]{16}$`. Skip an account on `SubscriptionRequiredException`.

### Signal 1 — GuardDuty AccessKey-type findings (if present; dual path; near-certain for compromised-credential types)
- Per the dual Access Mode path in [`step-3-collect-signals.md`](step-3-collect-signals.md). Keep **every** finding type (no type filter). The IAM compromised-credential types (resource type `AccessKey`) are the high-signal ones — e.g. the `CredentialAccess:IAMUser/*` family and the `AttackSequence:IAM/CompromisedCredentials` type. Verify exact type strings at run time against [GuardDuty IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html) and [attack-sequence finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-attack-sequence-finding-types.html); the catalog does not assert the full type list from memory.
- Missing detector in an account → finding "no GuardDuty detection coverage in account X" (Informational + recommendation), never silence.

### Signal 2 — IAM credential report (always; cheap; hygiene, not detection)
- `aws iam generate-credential-report` then `aws iam get-credential-report` per account (as [`iam-security-review`](../../iam-security-review/MODE.md) Step 3). The report is **up to 4 hours stale**, a single snapshot (so no "dormant then active" or "first password use" inference), reports only the first two keys per user, and contains **no access key IDs** (nothing to mask). Granularity caveats per [get_access_key_last_used](https://docs.aws.amazon.com/botocore/latest/reference/services/iam/client/get_access_key_last_used.html); credential-report column semantics per [getting-credential-reports](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html) (confirm staleness/column names at run time, do not assert from memory).
- Flag: `last_used_region` outside `expected_regions` (allowlist `us-east-1` for IAM/STS and `N/A` for non-regional services); an active root key (regardless of use); old unrotated keys with recent use; console users without MFA. For each flagged user: `list-access-keys --user-name` then `get-access-key-last-used` per key.
- Payer-only Cost Explorer anomalies (`ce get-anomalies`, `ce get-cost-and-usage` by region+service) as account-level context when the caller is the payer; unavailable to a non-payer setup.

### Signal 3 — opt-in, gated, visibly partial sample
Only when the operator opts in and only in named account/region pairs (`lookup-events` is newest-first and page-capped, so this is a sample, not a scan):
- one page of `lookup-events --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com` in `us-east-1` (all IAM mutations, one region),
- one page of `AttributeKey=Username,AttributeValue=root`,
- one page each for ~20 rare high-signal `EventName`s from [`event-catalog.md`](event-catalog.md) ("Signal-3 high-signal EventNames").
Group results by `userIdentity.accessKeyId` for **every** identity type (stolen instance creds appear as `AssumedRole`). **Report coverage by the earliest event returned**, never as a 7-day scan. No window widening (returns duplicates under a page cap). Valid `LookupAttributeKey` values per [LookupAttribute](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupAttribute.html).

**Output:** a ranked suspect table — masked key, owner, account, signals fired, first-seen, why, confidence — and `discovery-plan.json`. The operator picks subjects, which become the targeted path (Step 1a resolves them). If every signal is empty: report `no exposure signal observed; detection coverage: <list>` — **never an all-clear** (Risk Tier Informational, `badge--zinc`, never OK/green).

**Hard stops:** gate before fan-out; GuardDuty across many accounts × regions is expensive on `identity-center-direct` (see Step 3) — require named scope or a separate high-cost approval in the gate.
