# Cross-Account Defaults

Default configuration values used by all Corgiro modes. Operator-specific values in `~/.corgiro/config.json` override these.

> For how modes obtain credentials per account, see [credential-resolution.md](credential-resolution.md) — it dispatches on each roster entry's `via` field, and on `authMethod` for the operator's base session. The AssumeRole pattern below applies to the `cross-account-role` access mode under either `authMethod`.

| Key | Default | Description |
|-----|---------|-------------|
| `authMethod` | `identity-center` | How the operator obtains the base session: `identity-center` or `saml-external`. Absent ⇒ `identity-center`. |
| `authProfile` | `corgiro` | Base CLI profile holding the tooling-account session (`saml-external`; `auth.profile`) |
| `operatorRoleName` | `CorgiroOperator` | Operator role assumed in the tooling account (`saml-external`; must match the StackSet's `OperatorRoleName`) |
| `ssoSessionName` | `corgiro` | IAM Identity Center session name (`identity-center` only) |
| `profilePrefix` | `corgiro-` | Prefix for per-account CLI profiles (`<profilePrefix><accountId>`, `identity-center-direct` mode) |
| `permissionSetName` | `CorgiroOperator` | Permission set in the tooling account |
| `memberRoleName` | `CorgiroReadOnlyRole` | Role assumed in each member account |
| `externalId` | _(from operator config)_ | ExternalId for AssumeRole trust |
| `toolingAccountId` | _(from operator config)_ | Delegated admin account |
| `sessionDurationSeconds` | `3600` | STS session duration (hard ceiling 3600 — see below; clamp higher values) |
| `maxParallel` | `4` | Concurrent AssumeRole workers (hard ceiling 10 — clamp higher values) |
| `defaultRegions` | `auto` | Regions to probe (`auto` = discover per account) |
| `fallbackRegions` | `us-east-1, us-west-2, eu-west-1, ap-southeast-1` | Regions probed when `auto` discovery is unavailable (e.g. no payer-level Cost Explorer access) |
| `rosterFreshnessHours` | `24` | Re-fetch roster if older than this |
| `rosterStatePath` | `~/.corgiro/state/roster.json` | Cross-session roster snapshot |
| `coverageStatePath` | `~/.corgiro/state/coverage.json` | Cross-session coverage snapshot |
| `delegatedAdminAccountId` | _(optional; under `crossAccount.*`; `null` when unset)_ | `crossAccount.delegatedAdminAccountId` — account ID of the organization's delegated administrator for GuardDuty / Health / Security Hub / Config, under `cross-account-role`. Modes that query a delegated-admin API (e.g. `credential-exposure-triage` GuardDuty `list-members`) read this; if unset, the mode asks the operator once or falls back to its per-account path. The Roster does not record it. `setup-corgiro` is not changed to prompt for it — it is an optional hand-added field. |

> **`sessionDurationSeconds` cannot exceed 3600.** Corgiro always assumes `CorgiroReadOnlyRole` *from a role session* — Identity Center credentials are an `AWSReservedSSO_*` role session, and an external-IdP login is an `AssumeRoleWithSAML` role session. Both are **role chaining**, which STS caps at 1 hour regardless of the requested duration. Values above 3600 are clamped with a warning, not a failure. The StackSet template's `MaxSessionDurationSeconds` accepts up to 43200 because the role may also be assumed by a non-chained principal outside Corgiro; that headroom is unreachable through either Corgiro path.

## Region discovery (`account list-regions`)

When a mode needs the set of regions actually enabled for an account (rather than a static `defaultRegions` list), discover them with the Account Management API. `ListRegions` is **paginated** (`MaxResults` 1-50; response `NextToken` when more Regions remain — [ListRegions API](https://docs.aws.amazon.com/accounts/latest/reference/API_ListRegions.html)). A mode that counts calls needs **both** `--no-paginate` (so one CLI invocation is exactly one service request — without it the CLI auto-paginates and hides the request count) **and** a manual loop on the returned `NextToken` (so the Region list is complete). Decrement the mode's budget counters before each iteration. **Region discovery must not fail open:** if any request fails (throttling, `AccessDenied`, any error — [ListRegions errors](https://docs.aws.amazon.com/accounts/latest/reference/API_ListRegions.html)), abort discovery for that account, mark its footprint `partial` in `completeness.json`, and fall back to the configured `defaultRegions` / `expected_regions` — **never** treat the Regions accumulated before the failure as the complete footprint (a truncated list would silently drop every timeline/signal call for the missing Regions):

```bash
NEXT=""; REGIONS=""
while :; do
  # <decrement call_budget (this account) and global_call_budget here, before the request>
  if ! OUT="$(aws account list-regions --no-paginate \
    --region-opt-status-contains ENABLED ENABLED_BY_DEFAULT \
    --max-results=50 ${NEXT:+--next-token="$NEXT"})"; then
    # request failed: do NOT use the partial REGIONS as complete
    mark_footprint_partial "$ACCOUNT" "list-regions request failed"   # records partial in completeness.json
    REGIONS="$DEFAULT_REGIONS"                                        # fall back to configured defaultRegions / expected_regions
    break
  fi
  REGIONS="$REGIONS $(printf '%s' "$OUT" | jq -r '.Regions[].RegionName')"
  NEXT="$(printf '%s' "$OUT" | jq -r '.NextToken // empty')"
  [ -z "$NEXT" ] && break      # clean completion: REGIONS is the full enabled footprint
done
```

**Which pagination options to use.** `--max-results` and `--next-token` are the API's own `MaxResults` / `NextToken` request parameters; the API reference says the response `NextToken` "should be passed into the `next-token` request parameter of `list-regions`" ([ListRegions API](https://docs.aws.amazon.com/accounts/latest/reference/API_ListRegions.html)). The CLI reference page for the command lists instead the CLI's client-side pagination options `--starting-token` / `--page-size` / `--max-items` ([list-regions](https://docs.aws.amazon.com/cli/latest/reference/account/list-regions.html)); those drive the CLI's **automatic** pagination. **Observed on AWS CLI 2.x (not documented):** the CLI rejects those client-side options when combined with `--no-paginate` (`Cannot specify --no-paginate along with pagination arguments`), so they cannot implement a counted loop; and the CLI accepts an API request parameter such as `--next-token` even though the command's reference page does not list it (the client-side pagination options shadow it in the page, not in the parser). This is version-dependent behaviour, not a documented contract. The same rule applies to every manual `NextToken` / `Marker` loop in Corgiro: `--no-paginate` plus the service's own token parameter.

`list-regions` returns every Region and its opt-in status; filtering on `ENABLED`/`ENABLED_BY_DEFAULT` yields the account's active footprint. Source: [list-regions](https://docs.aws.amazon.com/cli/latest/reference/account/list-regions.html). With `--account-id` it can target a member account, but only from the organization's management or a delegated-administrator account ([list-regions](https://docs.aws.amazon.com/cli/latest/reference/account/list-regions.html)).

**Access-mode caveat.** `account:ListRegions` is **not** granted by the `SecurityAudit` or `ViewOnlyAccess` managed policies ([SecurityAudit reference](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html)), so under `identity-center-direct` a mode cannot rely on it — fall back to `defaultRegions` / the mode's `expected_regions`. Under `cross-account-role` it is available where `CorgiroReadOnlyRole` (`ReadOnlyAccess`) permits it. A mode that uses `list-regions` (e.g. `credential-exposure-triage`) documents this fallback rather than failing.

## Operator Config File (`~/.corgiro/config.json`)

Written by `setup-corgiro`. The `accessMode` field selects which block is populated; `authMethod` selects how the base session is obtained.

```json
{
  "accessMode": "cross-account-role",
  "authMethod": "identity-center",
  "ssoSession": { "sessionName": "corgiro", "startUrl": "https://ORG.awsapps.com/start", "ssoRegion": "us-east-1" },
  "identityCenter": null,
  "auth": null,
  "crossAccount": {
    "toolingAccountId": "123456789012",
    "externalId": "your-external-id-here",
    "memberRoleName": "CorgiroReadOnlyRole",
    "accountFilter": { "include": [], "exclude": [] },
    "delegatedAdminAccountId": null
  }
}
```

For `accessMode: "identity-center-direct"`, `crossAccount` is `null` and `identityCenter` carries `rolePriority`; per-account credentials come from `<profilePrefix><accountId>` CLI profiles (prefix from `identityCenter.profilePrefix`, default `corgiro-`) instead of AssumeRole.

### `authMethod: "saml-external"`

`ssoSession` is `null` and `auth` carries the base-profile details. Everything under `crossAccount` is unchanged — only how the tooling-account session is obtained differs.

```json
{
  "accessMode": "cross-account-role",
  "authMethod": "saml-external",
  "ssoSession": null,
  "identityCenter": null,
  "auth": {
    "profile": "corgiro",
    "loginCommand": "aws-azure-login --profile corgiro",
    "operatorRoleArn": "arn:aws:iam::123456789012:role/CorgiroOperator"
  },
  "crossAccount": {
    "toolingAccountId": "123456789012",
    "externalId": "your-external-id-here",
    "memberRoleName": "CorgiroReadOnlyRole",
    "accountFilter": { "include": [], "exclude": [] },
    "delegatedAdminAccountId": null
  }
}
```

`auth.loginCommand` is used only to print the correct re-login instruction on `auth_expired`; Corgiro never executes it. `auth.operatorRoleArn` must name the same role as the StackSet's `OperatorRoleName` parameter. See [credential-resolution.md](credential-resolution.md#auth-method-dispatch) for the preconditions, the invalid `identity-center-direct` combination, and the IdP-side residual risk.

## Per-Account AssumeRole Pattern

For services without an org-wide API:

1. `sts:AssumeRole` with `RoleArn = arn:aws:iam::<account-id>:role/CorgiroReadOnlyRole`, `ExternalId`, `DurationSeconds = 3600`, `RoleSessionName = corgiro-<operator>-<run_id>` (include the operator's SSO identity for CloudTrail attribution — see [credential-resolution.md](credential-resolution.md) for how to derive and sanitize `<operator>`)
2. Cache credentials in memory keyed by account ID. Refresh on `ExpiredToken`.
3. Run calls in parallel up to `maxParallel` workers (**hard ceiling 10** — clamp higher values). Exponential backoff on `ThrottlingException` (base 1s, cap 30s).
4. Persist per-account JSON under `<run_dir>/per-account/<account_id>/` before aggregating.

## When AssumeRole Fails

| Error | Cause & Remediation |
|-------|---------------------|
| `AccessDenied` on AssumeRole | Role missing or trust mismatch → deploy/refresh StackSet |
| `AccessDenied` with "external ID" | External ID mismatch → check `~/.corgiro/config.json` |
| Account `Status = SUSPENDED` | Skip; surface as "not eligible" |
| Management account | Use local credentials directly for org-level APIs |
