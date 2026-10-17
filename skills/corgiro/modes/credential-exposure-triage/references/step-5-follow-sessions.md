# Step 5 — Follow Hops, Derived Subjects, and Instance Sessions

Expand the subject graph **within caps, through a new expansion gate**. Every pivot value is regex-validated, taken from a designated response field, confined to accounts/regions already in `target-plan.json`, and batched: **one deduplicated expansion gate per hop depth; never gate or recurse one event at a time** (see MODE.md Safety and the identifier-passing pattern in [`ask/MODE.md`](../../ask/MODE.md)).

**Inputs:** `timeline/*` pages (Step 4); `target-plan.json`; caps `max_hops` (2), `max_sessions` (20), `max_derived_subjects` (10).

## Hops — STS chains
From **successful** `AssumeRole` / `GetFederationToken` / `GetSessionToken` events, take from `responseElements`:
- `credentials.accessKeyId` (an `ASIA…`, validated `^ASIA[0-9A-Z]{16}$`),
- `assumedRoleUser.arn` (validated as an ARN),
- the target account (validated `^[0-9]{12}$`).
If the target account is in the Roster, queue a Step 4 timeline for that `ASIA` key (new expansion gate, depth+1). If outside the Roster, record the attempt only (`in_roster: false`) — never follow. **Never recurse on a failed STS call.** Stop at `max_hops` / `max_sessions`, recording `reason_not_followed`.

## Derived subjects — attacker-created keys
From **successful** `CreateAccessKey`, take `responseElements.accessKey.accessKeyId` (validated `^AKIA[0-9A-Z]{16}$`) and queue it as a derived subject in the **same account**, up to `max_derived_subjects`. This is how attacker-created keys get their own timelines. Record in `sessions.json.derived_subjects`.

## Principal watchlist
`CreateUser` / `CreateLoginProfile` / `CreateRole` / `CreateInstanceProfile` feed `sessions.json.watchlist_principals` (validated IAM name `^[\w+=,.@-]{1,64}$`) for Step 6c lockout analysis.

## Instance-role session review
When the subject touched instances — `SendCommand`, `SendSSHPublicKey`, `AssociateIamInstanceProfile` — run a supplemental, gated lookup for the **instance** (an instance-role session, not an STS hop), with the instance ID validated `^i-[0-9a-f]{8,17}$` and passed via the JSON form of `--lookup-attributes` (never shorthand):
```
aws cloudtrail lookup-events \
  --lookup-attributes "$(printf '[{"AttributeKey":"Username","AttributeValue":"%s"}]' "$VALIDATED_INSTANCE_ID")" \
  --start-time <since> --end-time <until> --region <region> --no-paginate
```
Tag these pages `search: "username"` (file `<region>-un-pN.json`). `Username`-attribute results are supplemental: zero results never prove no activity, and they never count toward STILL ACTIVE.

## Caps and gates
- Each depth increment is one new expansion gate appended to `target-plan.json.expansions[]` with the batch of values, the field they came from, and the regex matched.
- `max_sessions` bounds total distinct hop sessions; `max_derived_subjects` bounds queued keys; `max_hops` bounds chain depth. A cap hit is recorded, not silently dropped.

**Dual Access Mode:** all calls are `cloudtrail:LookupEvents`, available on every path.

**Output:** `sessions.json` per [`state-contract.md`](state-contract.md) — the tree subject → hops → derived subjects, plus instance sessions and the watchlist.
