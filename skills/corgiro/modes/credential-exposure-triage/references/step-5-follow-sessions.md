# Step 5 — Follow Hops, Derived Subjects, and Instance Sessions

Expand the subject graph **within caps, through a new expansion gate**. Every pivot value is regex-validated, taken from a designated response field, confined to accounts/regions already in `target-plan.json`, and batched: **one deduplicated expansion gate per hop depth; never gate or recurse one event at a time** (see MODE.md Safety and the identifier-passing pattern in [`ask/MODE.md`](../../ask/MODE.md)).

**Inputs:** `timeline/*` pages (Step 4); `target-plan.json`; caps `max_hops` (2), `max_sessions` (20), `max_derived_subjects` (10).

## Hops — STS chains
From **successful** `AssumeRole` / `GetFederationToken` / `GetSessionToken` events — identified from the persisted (masked) timeline by their `(eventSource, eventName)` and `succeeded` outcome — take:
- the derived `ASIA…` key: read its **raw** value from the in-memory `sha256`→key map (populated in Step 4 before masking, keyed by the page's `responseElements.credentials.accessKeyId.sha256`); never read a raw key from a timeline file.
- `assumedRoleUser.arn`: this is an **assumed-role ARN** (`arn:aws:sts::<acct>:assumed-role/<role>/<session>`), **not** an IAM role ARN, so validate it with `re.fullmatch` body `arn:aws[a-z-]*:sts::[0-9]{12}:assumed-role/[A-Za-z0-9][A-Za-z0-9_+=.@-]{0,63}/[A-Za-z0-9*][A-Za-z0-9_+=,.@*-]{0,63}` ([ARN format](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html); the session segment may contain `*` after masking). This value is **recorded** in `sessions.json`, never substituted into a command.
- the target account (validated `re.fullmatch` body `[0-9]{12}`).
If the target account is in the Roster, queue a Step 4 timeline for that `ASIA` key (new expansion gate, depth+1). If outside the Roster, record the attempt only (`in_roster: false`) — never follow. **Never recurse on a failed STS call.** Stop at `max_hops` / `max_sessions`, recording `reason_not_followed`.

> **Denied cross-account AssumeRole is visible only in the caller's account.** CloudTrail does **not** log a denied cross-account `AssumeRole` attempt in the **target** account, so "attempted hop" evidence exists only in the caller's account ([IAM/STS CloudTrail integration](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)). A target-account timeline that shows no matching denied event is **not** proof the hop was not attempted; record such attempts from the caller-side event only.

## Derived subjects — attacker-created keys
From **successful** `CreateAccessKey`, the derived `AKIA…` key's raw value is read from the in-memory `sha256`→key map (keyed by the page's `responseElements.accessKey.accessKeyId.sha256`); queue it as a derived subject in the **same account**, up to `max_derived_subjects`. This is how attacker-created keys get their own timelines. Record in `sessions.json.derived_subjects`.

## Principal watchlist
The watchlist holds **only principals proven created by a successful `CreateUser` or `CreateRole`** (validated with `re.fullmatch` body `[A-Za-z0-9][A-Za-z0-9_+=.@-]{0,63}`). A successful `CreateLoginProfile` / `CreateInstanceProfile` / `AddRoleToInstanceProfile` is attached as an **artifact of an already-watchlisted created principal**, never as independent proof that its target principal is attacker-created — so Step 6c never excludes a pre-existing user from lockout analysis just because a login profile was set on it.

## Instance-role session review
When the subject touched instances — `SendCommand`, `SendSSHPublicKey`, `AssociateIamInstanceProfile` — run a supplemental, gated lookup for the **instance** (an instance-role session, not an STS hop), with the instance ID validated with `re.fullmatch` body `i-[0-9a-f]{8,17}` and passed via the JSON form of `--lookup-attributes` (never shorthand):
```
aws cloudtrail lookup-events \
  --lookup-attributes "$(printf '[{"AttributeKey":"Username","AttributeValue":"%s"}]' "$VALIDATED_INSTANCE_ID")" \
  --start-time <since> --end-time <until> --region <region> --no-paginate
```
Tag these pages `search: "username"`, `lookup_attribute: "Username"` (file `<region>-un-pN.json`). Instance-session `Username=<instance id>` results are supplemental: zero results never prove no activity, and they never count toward STILL ACTIVE. (A role-session subject's own `Username=<session name>` lookup in Step 4 is that subject's primary lookup and is tagged `primary`, not `username`.)

## Caps and gates
- Each depth increment is one new expansion gate appended to `target-plan.json.expansions[]` with the batch of values, the field they came from, and the regex matched.
- `max_sessions` bounds total distinct hop sessions; `max_derived_subjects` bounds queued keys; `max_hops` bounds chain depth. A cap hit is recorded, not silently dropped.
- **Budget (both counters, pre-call; Step 5 charges only its own calls).** The **instance-session lookup** issued directly by Step 5 decrements both `call_budget` (its account) and `global_call_budget` before the call. A queued hop/derived-subject timeline is **not** charged here — it is charged **once, by Step 4** when Step 4 runs it (no double-counting). Stop the account at its per-account cap (`partial — call budget exhausted`) and the whole run before a call that would exceed `global_call_budget` (`partial — global call budget exhausted`, recorded in `completeness.json`).

**Dual Access Mode:** all calls are `cloudtrail:LookupEvents`, available on every path.

**Output:** `sessions.json` per [`state-contract.md`](state-contract.md) — the tree subject → hops → derived subjects, plus instance sessions and the watchlist.
