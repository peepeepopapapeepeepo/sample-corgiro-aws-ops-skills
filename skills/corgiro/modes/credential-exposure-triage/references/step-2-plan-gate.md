# Step 2 — Plan Gate (mandatory; no exceptions)

Present the plan gate in the shape defined by [`../../../references/sweep-plan-coverage.md`](../../../references/sweep-plan-coverage.md) → "The plan gate", before any Step 3/4/5 fan-out. This mode's calls are fixed (not planned per-question), so the gate shows them pre-filled rather than inferred.

**Inputs:** `subjects.json` (Step 1a) or the operator's picks from `discovery-plan.json` (Step 1b); the caps and budget from Parameters.

**Show in the gate:**
- Accounts to query — **by default all reachable Roster Entries** (predeclared in `target-plan.json`), always including each subject's owning account; the operator narrows to an explicit list at the gate — and the enabled regions per account.
  - Resolve regions with `aws account list-regions --region-opt-status-contains ENABLED ENABLED_BY_DEFAULT` where permitted ([ListRegions](https://docs.aws.amazon.com/accounts/latest/reference/API_ListRegions.html)); this is documented once in [`../../../references/cross-account-defaults.md`](../../../references/cross-account-defaults.md). `account:ListRegions` is **not** in `SecurityAudit` or `ViewOnlyAccess`, so on `identity-center-direct` fall back to `expected_regions` / config `defaultRegions`.
- The exact lookup attributes and values, **masked** (e.g. `cloudtrail lookup-events AttributeKey=AccessKeyId AttributeValue=AKIA****XXXX`).
- The window (`since`..`until`) and whether it was clipped to CloudTrail's 90-day Event history: `clipped_to_90d` is **true when `since <= now − 90d`** (a window of exactly 90 days reaches the edge and is reported clipped) ([LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)).
- Estimated calls — a **lower bound** and a with-pagination figure (one CloudTrail page = one counted call). The **lower bound uses the low end of every range** and 1 CloudTrail page per region; the with-pagination figure uses the high end and the expected page count.
  - **resolution** (pre-gate, per subject): `get-caller-identity` (1) + `get-access-key-info` (1) + IAM reads on the principal (low end 6 for an AKIA, 0 for ViewOnly; high end 12) → lower bound **8**. For a `guardduty-finding` subject, add the Step 0 resolve calls already spent (`list-detectors` + `get-findings` = 2); for a `health-event` subject, add the Step 0 `describe-event-details` + `describe-affected-entities` = 2.
  - **per subject**: `Σ over accounts Σ over regions ( CloudTrail pages, low end 1 )` + GuardDuty per region (`list-detectors`+`list-members`+`list-findings`+`get-findings`, low end 3 + ⌈ids/50⌉) + Health (low end 1 per account) + credential report (low end 2 per account).
  - **per hop / derived subject**: add one per-region CloudTrail sweep (`regions × low end 1`).
  - State both figures and the per-term breakdown.
- The caps (`max_hops`, `max_sessions`, `max_derived_subjects`, `call_budget` per account, `global_call_budget` total across all accounts/regions/subjects/hops/follow-ups/import-validation, `max_parallel`) and any Roster Entries with `readOnlyEnforced: false` (residual risk). Show both the per-account `call_budget` and the run-wide `global_call_budget` in every gate; the estimate must be checked against `global_call_budget` and the gate must warn if the lower bound already approaches it.

**Persist `target-plan.json`** per [`state-contract.md`](state-contract.md). Execute **only** that contract.

**Expansion is a new gate.** Any expansion — a hop, a derived subject, a new account, a wider window — is a new expansion gate appended to `target-plan.json.expansions[]`, never a silent continuation. A hop or derived subject may only add lookup **values** inside already-approved accounts/regions, from a designated field, regex-validated, and listed in the gate before use (the validated-designated-identifier pattern reused from [`ask/MODE.md`](../../ask/MODE.md)). **Batch same-depth pivots into one deduplicated expansion gate; never gate or recurse one event at a time.** Nothing found in API output adds an account, region, or command beyond the plan.

**Manual pagination.** All lookups use `--no-paginate` with manual `NextToken`/`Marker` so one loop iteration = one counted call; CLI auto-pagination hides call counts and silently invalidates the budget. The token is passed back with the service's own request parameter (`--next-token` / `--marker`), never with the CLI's `--starting-token`, which the CLI rejects alongside `--no-paginate` — see "Which pagination options to use" in [`../../../references/cross-account-defaults.md`](../../../references/cross-account-defaults.md).

**Hard stops:**
- No fan-out before explicit approval; edits re-render the gate.
- An account hitting `call_budget` mid-run is stopped and marked `partial — call budget exhausted` (recorded in `completeness.json`), not silently truncated.

**Output:** `target-plan.json`.
