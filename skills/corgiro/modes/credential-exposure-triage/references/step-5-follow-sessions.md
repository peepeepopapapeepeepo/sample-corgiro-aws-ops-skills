# Step 5 — Follow Hops, Derived Subjects, and Instance Sessions

Expand the subject graph **within caps, through a new expansion gate**. Every pivot value is regex-validated, taken from a designated response field, confined to accounts/regions already in `target-plan.json`, and batched: **one deduplicated expansion gate per hop depth; never gate or recurse one event at a time** (see MODE.md Safety and the identifier-passing pattern in [`ask/MODE.md`](../../ask/MODE.md)).

**Inputs:** `timeline/*` pages (Step 4); `target-plan.json`; caps `max_hops` (2), `max_sessions` (20), `max_derived_subjects` (10).

## Hops — STS chains
From **successful** `AssumeRole` / `GetFederationToken` / `GetSessionToken` events — identified from the persisted (masked) timeline by their `(eventSource, eventName)` and `succeeded` outcome — take:
- the derived `ASIA…` key: read its **raw** value from the in-memory `sha256`→key map (populated in Step 4 before masking, keyed by the page's `responseElements.credentials.accessKeyId.sha256`); never read a raw key from a timeline file.
- `assumedRoleUser.arn` (validated as a role ARN, `\A[A-Za-z0-9]...` per the handoff ARN pattern),
- the target account (validated `\A[0-9]{12}\z`).
If the target account is in the Roster, queue a Step 4 timeline for that `ASIA` key (new expansion gate, depth+1). If outside the Roster, record the attempt only (`in_roster: false`) — never follow. **Never recurse on a failed STS call.** Stop at `max_hops` / `max_sessions`, recording `reason_not_followed`.

## Derived subjects — attacker-created keys
From **successful** `CreateAccessKey`, the derived `AKIA…` key's raw value is read from the in-memory `sha256`→key map (keyed by the page's `responseElements.accessKey.accessKeyId.sha256`); queue it as a derived subject in the **same account**, up to `max_derived_subjects`. This is how attacker-created keys get their own timelines. Record in `sessions.json.derived_subjects`.

## Principal watchlist
The watchlist holds **only principals proven created by a successful `CreateUser` or `CreateRole`** (validated IAM name `\A[A-Za-z0-9][\w+=.@-]{0,63}\z`). A successful `CreateLoginProfile` / `CreateInstanceProfile` / `AddRoleToInstanceProfile` is attached as an **artifact of an already-watchlisted created principal**, never as independent proof that its target principal is attacker-created — so Step 6c never excludes a pre-existing user from lockout analysis just because a login profile was set on it.

## Instance-role session review
When the subject touched instances — `SendCommand`, `SendSSHPublicKey`, `AssociateIamInstanceProfile` — run a supplemental, gated lookup for the **instance** (an instance-role session, not an STS hop), with the instance ID validated `\Ai-[0-9a-f]{8,17}\z` and passed via the JSON form of `--lookup-attributes` (never shorthand):
```
aws cloudtrail lookup-events \
  --lookup-attributes "$(printf '[{"AttributeKey":"Username","AttributeValue":"%s"}]' "$VALIDATED_INSTANCE_ID")" \
  --start-time <since> --end-time <until> --region <region> --no-paginate
```
Tag these pages `search: "username"` (file `<region>-un-pN.json`). `Username`-attribute results are supplemental: zero results never prove no activity, and they never count toward STILL ACTIVE.

## Caps and gates
- Each depth increment is one new expansion gate appended to `target-plan.json.expansions[]` with the batch of values, the field they came from, and the regex matched.
- `max_sessions` bounds total distinct hop sessions; `max_derived_subjects` bounds queued keys; `max_hops` bounds chain depth. A cap hit is recorded, not silently dropped.
- **Budget (both counters, pre-call).** The instance-session lookup and each queued hop/derived Step-4 sweep decrement both `call_budget` and `global_call_budget` before the call; stop the account at the per-account cap (`partial — call budget exhausted`) and stop the whole run before a call that would exceed `global_call_budget` (`partial — global call budget exhausted`, recorded in `completeness.json`).

**Dual Access Mode:** all calls are `cloudtrail:LookupEvents`, available on every path.

**Output:** `sessions.json` per [`state-contract.md`](state-contract.md) — the tree subject → hops → derived subjects, plus instance sessions and the watchlist.
