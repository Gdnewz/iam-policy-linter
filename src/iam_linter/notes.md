# iam-policy-linter — project notes

My own reference for this project. Read top to bottom to understand what the
linter is, how it's built, and why each piece exists.

---

## 1. What this project is

A command-line tool that scans AWS IAM policies (and some account settings) and
reports security problems — overly broad permissions, missing MFA, stale access
keys. "Linter" because it's like a code linter, but for permissions instead of
code style.

The core idea: **permissions should be as narrow as possible.** Most real AWS
breaches come from a policy that granted more than it needed. This tool finds
those before an attacker does.

---

## 2. How the code is laid out

```
src/iam_linter/
  models.py    # the data shapes: Policy (input) and Finding (output)
  checks.py    # the actual rules — each one takes data, returns findings
  client.py    # talks to AWS via boto3 (list users, keys, etc.)
  cli.py       # wires it together for the command line
tests/
  test_checks.py   # tests for every check, using fake data / fake AWS
LEARNING.md    # the exercises I work through
```

The split that matters: **checks.py never calls AWS.** Checks are pure
functions — data in, findings out — so I can test them instantly with a
hand-written dict and no network. **client.py** is the only place that touches
AWS. Keeping those apart is what makes the whole thing testable.

---

## 3. IAM policies — the concepts the checks rely on

An IAM policy is JSON describing who can do what. The rules:

- **Deny by default.** If nothing grants access, there is none.
- **Allow grants, explicit Deny always wins.** A Deny beats any Allow.
- `"Action": "*"` means every API call in every service.
- `"Resource": "*"` means every resource.
- **Allow + Action:\* + Resource:\* + no Condition == full admin.** The single
  most dangerous statement that can exist. That's check #1.
- `"Condition"` narrows a statement (by IP, MFA, time, tag…). A sensitive action
  with no Condition is broader than it probably needs to be.

A policy's `Statement` can be a single dict OR a list of dicts — IAM allows
both. That's why there's a `statements()` helper that always hands back a list.

---

## 4. The data model (models.py)

**Policy** — the input. Has `name`, `arn`, `attached_to`, and `document` (the
raw JSON dict).

**Finding** — the output. One problem the linter found. Required fields:
- `severity` — "HIGH" | "MEDIUM" | "LOW"
- `check` — short id of the rule that fired, e.g. "wildcard-admin"
- `policy_name`
- `resource` — what the problem is attached to
- `message` — human-readable description
- `statement` — optional (defaults to `{}`), the offending statement for context

Both are dataclasses. A dataclass is just a class where Python writes the
boilerplate `__init__` for me from the field list.

---

## 5. The checks — the pattern every rule follows

Every check is the same shape:

```python
def check_something(policy: Policy) -> list[Finding]:
    findings = []
    for stmt in statements(policy):
        if not is_allow(stmt):
            continue              # skip non-Allow statements
        if <this statement is a problem>:
            findings.append(Finding(severity=..., check=..., ...))
    return findings
```

The pattern: **empty list → loop → `continue` past what's fine → append what's
not → return the list.** I use this everywhere (also in FitFindr). The
`continue` is "this one's safe, skip it"; the append only happens for real
problems.

Helpers in checks.py that keep the checks clean:
- `statements(policy)` — statements as a list, whatever shape IAM gave.
- `_as_list(x)` — wraps a single value in a list; `Action` can be one string or
  many, this normalizes it.
- `actions_of(stmt)` / `resources_of(stmt)` — the actions/resources as a list.
- `is_allow(stmt)` — True if `Effect == "Allow"`. Uses `.get` so a missing
  field doesn't crash.

### The three policy checks
1. **wildcard-admin (HIGH)** — Allow + Action `"*"` + Resource `"*"`. Full admin.
2. **service-wildcard (MEDIUM/HIGH)** — an action ending in `":*"` (like `s3:*`)
   on Resource `"*"`. HIGH if the service is `iam` or `sts` (those let you grant
   yourself anything), MEDIUM otherwise. `action.split(":")[0]` pulls the
   service name off the front.
3. **sensitive-no-condition (MEDIUM)** — an action from `SENSITIVE_ACTIONS`
   (PassRole, AssumeRole, Decrypt, StopLogging…) allowed with no `Condition`.
   `stmt.get("Condition")` is falsy when absent.

---

## 6. The registry and run_checks

`ALL_CHECKS` is a list of check functions. `run_checks` loops every policy and
runs every check in the list against it:

```python
def run_checks(policies, checks=None):
    checks = checks or ALL_CHECKS
    findings = []
    for policy in policies:
        for check in checks:
            findings.extend(check(policy))
    return findings
```

To enable a new policy check, add it to `ALL_CHECKS`. That's the only wiring.

**Important design point:** `run_checks` passes a *Policy* to every check. So a
check that takes something else (like user rows) can't go in `ALL_CHECKS` — it
would be handed a Policy and break. Account-level checks need their own path
(see §8).

---

## 7. Talking to AWS (client.py, boto3)

boto3 is the Python library for AWS. Three patterns here matter:

### a) The injectable client (`iam=None`)
```python
def get_users_with_mfa_status(iam=None):
    iam = iam or boto3.client("iam")
    ...
```
- If a client is passed, use it; if not, make a real one.
- Why not default it in the signature (`iam=boto3.client("iam")`)? Defaults run
  ONCE when the file is imported — it would try to hit AWS the moment the module
  loads, before any test could swap in a fake. Making it inside the body means
  it only runs when called, and only if nothing was passed.
- This is what lets tests inject **moto** (fake AWS) so they never touch the
  real account.
- Pattern to remember: `thing = thing or make_default()`.

### b) Pagination
AWS returns results in PAGES — one `list_users()` call might be just the first
chunk plus a "there's more" marker. Reading only page one misses users on a big
account. boto3's paginator handles the marker loop:
```python
paginator = iam.get_paginator("list_users")
for page in paginator.paginate():
    for u in page["Users"]:
        name = u["UserName"]
```
Outer loop = pages, inner loop = items on that page.

### c) Exceptions as control flow
Some facts have no boolean field — you learn them by whether a call raises:
```python
try:
    iam.get_login_profile(UserName=name)
    has_console_password = True
except iam.exceptions.NoSuchEntityException:
    has_console_password = False
```
If the call succeeds, the user has a console login. If it RAISES
NoSuchEntityException, that's AWS saying "no console password" — an API-only
user. Catching the error IS the detection. Normal in boto3, not a hack.

Empty-list checks are simpler: `bool(mfa_devices)` — an empty list is falsy, so
no MFA. No need for `len() > 0`.

---

## 8. Account checks vs policy checks

Policy checks (§5) take a Policy. **Account checks** take a snapshot of the
account (users, keys) instead:

- `get_users_with_mfa_status()` — returns `[{"user", "has_console_password",
  "mfa_enabled"}, ...]` for every user.
- `check_no_mfa(user_rows)` — turns those rows into HIGH findings for users who
  have a console password but no MFA. The dangerous combo: they can log into
  the web console and only a password protects them.

Because these take user rows, not a Policy, they don't belong in `ALL_CHECKS`.
The clean fix is a second registry, `ACCOUNT_CHECKS`, with its own runner that
feeds the account snapshot. (Loose end: `check_no_mfa` passes its test but isn't
wired to the CLI yet via that path.)

### Why MFA matters (ties to the CYB101 cracking lab)
MFA = Multi-Factor Authentication — a second proof beyond the password (a phone
code or hardware key). A password alone can be phished, guessed, or cracked
(exactly what the password lab did to 1000 hashes). With MFA on, a stolen
password isn't enough — the attacker also needs the physical device. A user
with a password and no MFA is one stolen password away from a breach.

---

## 9. Access keys and datetime (exercise 4 concept)

`get_access_keys()` — every access key with its age; then `check_stale_access_key`
flags keys older than 90 days (credential hygiene — old keys that never rotate
are a risk).

The new trap: AWS returns `CreateDate` as a **timezone-aware** datetime. To get
an age you subtract it from "now" — but it has to be timezone-aware "now":
```python
from datetime import datetime, timezone
age = datetime.now(timezone.utc) - key["CreateDate"]
```
`datetime.now()` with no timezone is "naive" and subtracting a naive from an
aware datetime raises `TypeError`. Lesson: when doing time math against AWS,
always use timezone-aware now.

Testing time-dependent code: moto creates keys "now", so they never look old.
Either control the clock or make the check accept a `now=` parameter you can set
from the test — the second is better design, because the function stays testable
without patching global state.

---

## 10. Testing with moto

moto is a library that fakes AWS in memory. Tests spin up a fake IAM, create
fake users/keys, call the function with that fake client, and assert on the
result — no real AWS, no network, fast and free. This only works because the
functions accept an injected client (§7a).

Run all tests: `pytest`. Output like `15 passed, 1 xfailed` means 15 green and
1 marked "expected to fail" (an exercise I haven't finished — the xfail marker
hides it until I remove it).

Workflow for each exercise: read the spec → find the helper that already exists
→ write one piece → run pytest → repeat. Build small, test often.

---

## 11. CI (continuous integration)

GitHub Actions runs `pytest` automatically on every push. Green check = tests
pass on a clean machine, not just mine. CI is the "I" in CI/CD — it catches a
break the moment it's pushed, before it reaches anyone else.

---

## 12. Bugs I actually hit (so I stop repeating them)

- **Append outside the loop.** Indentation decides what's inside a loop. An
  append lined up with the `for` instead of inside it runs once and keeps only
  the last item. Everything per-item goes INSIDE the inner loop.
- **Client in the signature.** `def f(iam=boto3.client("iam"))` runs at import
  time and hits AWS before tests can inject a fake. Put it in the body:
  `iam = iam or boto3.client("iam")`.
- **Dead code after return.** A `raise NotImplementedError()` left after
  `return findings` never runs — delete it once the function works.
- **`return bool` vs `return True`.** Writing a type/method name without calling
  or using it gives back the object, not a value. (Same family: `p.strip().upper`
  with no `()` is the method, not the uppercased string.)
- **Order in `and`.** `and` evaluates left to right and short-circuits — put the
  guard (`x is not None`) on the LEFT so the risky comparison never runs when
  it shouldn't.
- **VS Code doesn't autosave.** Identical test output before and after an edit
  almost always means the file wasn't saved. Ctrl+S, then run.

---

## 13. The security story in one paragraph

Narrow permissions, require a Condition on dangerous actions, never grant
`iam:*`/`sts:*` broadly, force MFA on anyone with console access, and rotate
access keys. Every check in this tool is one of those principles turned into
code. The password lab showed how a weak secret falls; this tool is the other
side — making sure that even if one secret falls, it isn't enough, and that no
single identity holds more power than it needs.

---

## 14. datetime & timedelta (the exercise 4 math)

AWS gives dates as **timezone-aware** datetimes. To find how old something is,
subtract it from "now":

```python
from datetime import datetime, timezone

now = datetime.now(timezone.utc)      # current time, timezone-aware (UTC)
age = now - key["created"]            # a timedelta: a DURATION
age_days = age.days                   # whole days as an int
```

Key ideas:

- **datetime** = a point in time ("2026-10-03 14:30 UTC"). **timedelta** = a
  length of time ("137 days, 4 hours"). Subtracting two datetimes gives a
  timedelta.
- `.days` on a timedelta pulls out just the whole-day count as an integer, which
  is what the 90-day check compares against (`age.days > 90`).
- **The trap:** both sides of the subtraction must be timezone-aware, or Python
  raises `TypeError: can't subtract offset-naive and offset-aware datetimes`.
  `datetime.now()` with no argument is *naive* (no timezone) and will crash
  against AWS's aware dates. Always `datetime.now(timezone.utc)` when comparing
  to AWS.
- **The injectable clock (`now=None`):** real runs compute `now`; tests pass a
  fixed `now` so a key can be made to "look old" on demand. Same pattern as the
  injectable `iam=None` client — and for the same reason, it goes in the function
  BODY (`now = now or datetime.now(timezone.utc)`), never as a signature default
  (a default evaluates once at import, freezing "now" at import time).

Why it matters: stale access keys that never rotate are a credential-hygiene
risk — an old leaked key keeps working forever. `check_stale_access_key` flags
keys older than 90 days as MEDIUM.

### f-strings (used in the messages)
`f"user/{key['user']}"` — the `f` prefix lets you drop variables into a string
inside `{ }`. `{key['user']}` is replaced with the actual value, so it becomes
`"user/alice"`. Note the inner quotes are single (`'user'`) because the string
itself uses double quotes — don't nest the same quote type.

---

## 15. Exercise status

- [x] Exercise 1 — check_service_wildcard
- [x] Exercise 2 — check_sensitive_action_without_condition
- [x] Exercise 3 — get_users_with_mfa_status + check_no_mfa
- [ ] Exercise 4 — get_access_keys + check_stale_access_key (datetime/timezone)
- [ ] Exercise 5 — unused permissions (async job: start → poll → read), optional
- [ ] Loose end — wire account checks to the CLI via an ACCOUNT_CHECKS registry