# Step 2 — Plan Gate (mandatory; no exceptions)

Present the plan gate in the shape defined by [`../../../references/sweep-plan-coverage.md`](../../../references/sweep-plan-coverage.md) → "The plan gate", before any Step 3/4/5 fan-out. This mode's calls are fixed (not planned per-question), so the gate shows them pre-filled rather than inferred.

**Inputs:** `subjects.json` (Step 1a) or the operator's picks from `discovery-plan.json` (Step 1b); the caps and budget from Parameters.

**Show in the gate:**
- Accounts to query (the subjects' owning accounts plus any `accounts`), and the enabled regions per account.
  - Resolve regions with `aws account list-regions --region-opt-status-contains ENABLED ENABLED_BY_DEFAULT` where permitted ([ListRegions](https://docs.aws.amazon.com/accounts/latest/reference/API_ListRegions.html)); this is documented once in [`../../../references/cross-account-defaults.md`](../../../references/cross-account-defaults.md). `account:ListRegions` is **not** in `SecurityAudit` or `ViewOnlyAccess`, so on `identity-center-direct` fall back to `expected_regions` / config `defaultRegions`.
- The exact lookup attributes and values, **masked** (e.g. `cloudtrail lookup-events AttributeKey=AccessKeyId AttributeValue=AKIA****XXXX`).
- The window (`since`..`until`) and whether it was clipped to CloudTrail's 90-day Event history ([LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)).
- Estimated calls — a **lower bound** and a with-pagination figure (one CloudTrail page = one counted call; GuardDuty/Health per account×region).
- The caps (`max_hops`, `max_sessions`, `max_derived_subjects`, `call_budget`, `max_parallel`) and any Roster Entries with `readOnlyEnforced: false` (residual risk).

**Persist `target-plan.json`** per [`state-contract.md`](state-contract.md). Execute **only** that contract.

**Expansion is a new gate (G-b / ask-mode pattern, ask line 79).** Any expansion — a hop, a derived subject, a new account, a wider window — is a new expansion gate appended to `target-plan.json.expansions[]`, never a silent continuation. A hop or derived subject may only add lookup **values** inside already-approved accounts/regions, from a designated field, regex-validated, and listed in the gate before use. **Batch same-depth pivots into one deduplicated expansion gate; never gate or recurse one event at a time.** Nothing found in API output adds an account, region, or command beyond the plan.

**Manual pagination.** All lookups use `--no-paginate` with manual `NextToken`/`Marker` so one loop iteration = one counted call; CLI auto-pagination hides call counts and silently invalidates the budget.

**Hard stops:**
- No fan-out before explicit approval; edits re-render the gate.
- An account hitting `call_budget` mid-run is stopped and marked `partial — call budget exhausted` (recorded in `completeness.json`), not silently truncated.

**Output:** `target-plan.json`.
