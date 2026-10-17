# Step 1a — Resolve Subject(s)

**Inputs:** subject parameters from MODE.md; the Roster (`~/.corgiro/state/roster.json`); the pre-flight result.

**Allowed calls** (all read-only; dispatch per [`../../../references/credential-resolution.md`](../../../references/credential-resolution.md) on the owning account's Roster Entry `via`):
- `aws sts get-access-key-info --access-key-id "$COMPROMISED_ACCESS_KEY_ID"` — returns the owning account ID. `AKIA…` = long-term IAM-user or root credentials; `ASIA…` = temporary STS credentials. It says nothing about key state. Source: [GetAccessKeyInfo](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetAccessKeyInfo.html).
- For an `AKIA` subject, once the owning account is a reachable Roster Entry and you have a session in it:
  - `aws iam get-access-key-last-used --access-key-id "$COMPROMISED_ACCESS_KEY_ID"` → `UserName`, `LastUsedDate`, `ServiceName`, `Region`. Granularity note: last-used reflects activity that "usually appears within four hours" and has been tracked only since 2015-04-22; a single snapshot, not a history. Source: [get_access_key_last_used](https://docs.aws.amazon.com/botocore/latest/reference/services/iam/client/get_access_key_last_used.html).
  - `aws iam list-access-keys --user-name <name>` (all keys on the principal), `list-attached-user-policies`, `list-user-policies`, `list-groups-for-user` (+ each group's `list-attached-group-policies` / `list-group-policies`), `get-login-profile`, `list-mfa-devices`.
- `aws iam list-attached-user-policies` / `list-attached-role-policies` on the principal to detect `AWSCompromisedKeyQuarantineV2`/`V3` ([V2](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV2.html), [V3](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV3.html)); record in `subjects.json.quarantine_policy`.

**Resolve order (non-circular):**
1. **Probe the base principal's own permission.** For `cross-account-role`, first probe whether the current operator base principal can call `sts:GetAccessKeyInfo` (it is a caller-self API, not a member-account read).
   - If it **can**, call `sts get-access-key-info` from the base session to learn the owning account.
   - If it **cannot** (the tooling operator role does not grant it), require an operator-supplied `account_id`, or a GuardDuty/Health subject that already supplies the account; a raw-key-only subject with no resolvable account stops as `unresolved-account`.
   For `identity-center-direct`, call `sts get-access-key-info` from the per-account session that has it (SecurityAudit), or require operator-supplied account under ViewOnlyAccess.
2. If the owning account is **not** a reachable Roster Entry → stop this subject with `account-outside-roster` (Corgiro cannot trace into an account it cannot reach). Record and continue with other subjects.
3. Otherwise acquire that account's Roster Entry session and run the `AKIA` IAM calls above **in that account**.

**Dual Access Mode:**
- `cross-account-role` — resolve and all IAM reads run in the owning account via its `assume-role` Roster Entry session, never from the tooling account (which has no `sts:GetAccessKeyInfo` / `iam:*` on members).
- `identity-center-direct` with `SecurityAudit` — same calls via the per-account SSO profile.
- `identity-center-direct` with `ViewOnlyAccess` — `sts:GetAccessKeyInfo` and `iam:GetAccessKeyLastUsed` are **not** granted; the operator must supply the owning `account_id` and the IAM user/role `name`, and `last_used` is recorded `not-observable`. Degrade, do not fail (MODE.md Prerequisites).

**Subject-kind handling:**
- `guardduty-finding` / `health-event` — the Step 0 resolve call(s) already produced the key + principal + account (GuardDuty: `get-findings`; Health: `describe-event-details` + `describe-affected-entities`); populate `subjects.json` from them, then run the `AKIA` IAM reads if the resolved key is `AKIA` and permitted.
- `role-session` (`role_arn` + `session_name` + `account_id`) — the account is given; resolve the role and record it as the subject principal.
- Bare `ASIA` with no role/account/time — best-effort: Step 4 searches for any event made with it and derives the role/session from that event's `userIdentity`; if none is found, mark the subject `unresolved`. An `ASIA` key cannot be traced to its issuing STS event by an `AccessKeyId` lookup.

**Hard stops:**
- Never print or persist the raw key (MODE.md Safety) — populate `key` as `{masked, sha256}`.
- Wording for authorization: record "identity-policy grants observed; effective authorization not determined" — SCPs, permission boundaries, session/resource policies, and explicit denies are **not** visible from these calls.
- Do **not** here run the `ResourceName=<principal>` CloudTrail search for events done *to* the principal: that lookup feeds API output into a command and is gated. It runs in **Step 4** (after the Step 2 gate) with the IAM-name regex, not in Step 1 (guardian item 2).

**Output:** `subjects.json` per [`state-contract.md`](state-contract.md). One entry per subject, with `status` set. Partial resolution (account known, name unknown under ViewOnlyAccess) is `degraded-view-only`, not an error.
