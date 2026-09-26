# Learning guide

This repo is a working v0.1 plus a set of exercises. Do them in order; each
one has tests already written for it. Your job is to make the red tests green.

Rule for the whole project: **never paste code you don't understand.** If you
get stuck, read the hint, read the AWS docs page, try again. Only then ask for
help, and ask a specific question ("why does moto raise X here?").

Start by running the suite once so you know the baseline:

```bash
pytest -v          # expect: 8 passed, 8 xfailed
```

`xfailed` = "expected to fail". Those are your exercises. Each one is marked
with `@pytest.mark.xfail(...)`. When you implement something, delete that
decorator line and run the tests again.

---

## Day 1 — read before you write (1–2 hours)

Read the files in this order. Each has a docstring at the top explaining
what it's for and why it's separate.

1. `models.py`   — the two data shapes everything else uses
2. `checks.py`   — read `check_wildcard_admin` line by line
3. `tests/test_checks.py` — see how the tests build fake policies
4. `client.py`   — the boto3 calls
5. `cli.py`      — how it all gets wired together

Then do this deliberately:

```bash
pytest -v tests/test_checks.py             # green
# open checks.py, change '"*" in actions_of(stmt)' to '"**" in ...'
pytest -v tests/test_checks.py             # watch it go red, read the assertion
# change it back
```

Questions to answer for yourself (write the answers in a notes file):
- Why does `statements()` exist? What breaks if you remove it?
- Why doesn't `check_wildcard_admin` call boto3?
- What does `@mock_aws` actually do in `test_client.py`?

## Exercise 1 — `check_service_wildcard`  (checks.py)

Goal: flag `Allow` statements where any action ends in `:*` and Resource
includes `*`. `iam:*` and `sts:*` are HIGH; everything else MEDIUM.

Steps:
1. Copy the shape of `check_wildcard_admin`. Same loop, different condition.
2. `for act in actions_of(stmt): if act.endswith(":*"): ...`
3. Pull the service name with `act.split(":")[0]` and pick severity.
4. Remove the xfail decorator from `TestServiceWildcard`, run tests.
5. Uncomment the check in `ALL_CHECKS`.

Concept you're learning: how IAM actions are namespaced (`service:Action`),
and why `iam:*` is effectively the same as `*`.

## Exercise 2 — `check_sensitive_action_without_condition`  (checks.py)

Goal: flag sensitive actions (see `SENSITIVE_ACTIONS`) that have no `Condition`.

Steps:
1. Skip statements where `stmt.get("Condition")` is truthy.
2. For each action in the statement, check membership in `SENSITIVE_ACTIONS`.
3. One Finding per matched action, action name in the message.
4. Stretch: use `fnmatch.fnmatch("iam:PassRole", "iam:*")` so wildcards also
   match. Write an extra test for it.

Concept: what IAM Conditions are for. Read the docs page on
`iam:PassedToService` — it's the classic example of a condition that turns
a dangerous permission into a safe one.

## Exercise 3 — `get_users_with_mfa_status`  (client.py)

Goal: for each IAM user, does it have a console password, and does it have MFA?

Steps:
1. Paginate `list_users`.
2. `get_login_profile` raises `NoSuchEntityException` for API-only users.
   Catch it: `except iam.exceptions.NoSuchEntityException:`. This is the
   *normal* way to detect it — there is no "has_password" boolean.
3. `list_mfa_devices(UserName=...)["MFADevices"]` — empty list means none.
4. Then write a NEW check in `checks.py` (`check_no_mfa`) that turns those
   rows into HIGH findings. Note: this check takes user rows, not a Policy,
   so it won't fit `run_checks` as-is. Decide how to handle that — that
   design decision is part of the exercise. (One option: a second registry
   `ACCOUNT_CHECKS` that takes the whole account snapshot.)

Concept: exceptions as control flow in boto3, and the difference between
console access and programmatic access.

## Exercise 4 — `get_access_keys`  (client.py)

Goal: every access key with its age. Then a `check_stale_access_key` for
keys older than 90 days.

Steps:
1. Paginate users, call `list_access_keys` for each.
2. `CreateDate` is timezone-aware. Compute age with
   `datetime.now(timezone.utc) - key["CreateDate"]`. Using naive
   `datetime.now()` will raise `TypeError` — try it once so you remember.
3. Write the check and a test. For the test you'll need a key that *looks*
   old. moto keys are created "now", so either monkeypatch the clock or make
   the check accept a `now=` parameter you can control from the test.
   The second option is better design; think about why.

Concept: credential hygiene, and writing time-dependent code that is testable.

## Exercise 5 — unused permissions (harder, optional for v0.2)

`iam.generate_service_last_accessed_details(Arn=policy_arn)` starts an
asynchronous job; you then poll `get_service_last_accessed_details(JobId=...)`
until `JobStatus == "COMPLETED"`. Compare the services the policy *allows*
against the ones with a recent `LastAuthenticated`.

This one is a real-world pattern (start job → poll → read result) that you'll
see everywhere in AWS. moto's support for it is partial, so you may need to
test it against your real account. That's fine — this is the point where you
run the tool for real.

## Running it for real

1. Create a personal AWS account. Set a billing alarm at $5 before anything else.
2. Create an IAM user with the AWS-managed `SecurityAudit` policy attached.
   Generate an access key, configure it: `aws configure --profile lint`.
3. Create a deliberately bad policy in the console (Action `*`, Resource `*`)
   and attach it to a test role.
4. `iam-linter --profile lint` — it should find it.
5. Screenshot the output for the README. Delete the bad policy.

## When you finish v0.2

Write the README "Why" section in your own words, add a short architecture
diagram (even ASCII), and post the repo link in your CodePath Slack. Then move
to project 2 (CloudTrail anomaly detector) — you'll reuse `client.py`'s
pagination pattern and the same fetch/judge split.
