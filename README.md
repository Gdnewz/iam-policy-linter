# iam-policy-linter

A command-line tool that scans an AWS account's IAM policies for risky patterns
and reports them as a table or JSON. Exits non-zero on HIGH findings so it can
gate a CI pipeline.

```
                              IAM findings (1)
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Check          ┃ Policy  ┃ Where           ┃ Message              ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH     │ wildcard-admin │ GodMode │ role/Deploy     │ Statement allows     │
│          │                │         │                 │ Action "*" on        │
│          │                │         │                 │ Resource "*"         │
└──────────┴────────────────┴─────────┴─────────────────┴──────────────────────┘
```

## Why

Over-permissive IAM is the most common root cause in cloud breaches. AWS's own
tooling (IAM Access Analyzer) is good but account-by-account and click-heavy.
This tool gives a one-command, scriptable view you can run in CI or across
accounts.

## Checks

| id | severity | what it finds | status |
|---|---|---|---|
| `wildcard-admin` | HIGH | `Allow` + `Action:"*"` + `Resource:"*"` | done |
| `service-wildcard` | MEDIUM/HIGH | `s3:*`, `iam:*` etc. on `Resource:"*"` | planned |
| `sensitive-no-condition` | MEDIUM | `iam:PassRole`, `sts:AssumeRole`, ... with no `Condition` | planned |
| `no-mfa` | HIGH | console users without MFA | planned |
| `stale-access-key` | MEDIUM | access keys older than 90 days | planned |
| `unused-permissions` | LOW | services a policy allows but nobody has used in 90 days | planned |

## Install

```bash
git clone <your repo url>
cd iam-policy-linter
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Run

Needs read-only IAM credentials (the AWS-managed `SecurityAudit` policy is enough).

```bash
iam-linter                        # table to terminal
iam-linter --json findings.json   # also write JSON
iam-linter --profile dev          # named AWS CLI profile
iam-linter --fail-on MEDIUM       # stricter CI gate
```

## Test

```bash
pytest -v
```

Tests never touch real AWS. `tests/test_checks.py` feeds hand-written policy
documents to each check; `tests/test_client.py` runs against an in-memory fake
AWS provided by [moto](https://github.com/getmoto/moto).

## Layout

```
src/iam_linter/
  models.py   Policy and Finding dataclasses
  client.py   everything that calls AWS (fetch only, no judgement)
  checks.py   pure functions: Policy -> list[Finding]
  report.py   table / JSON output
  cli.py      argument parsing and exit codes
tests/
```

The split between `client.py` (fetch) and `checks.py` (judge) is the main
design decision: checks are pure functions, so they're trivial to test and
easy to add.

## Roadmap

- v0.1  fetch policies, wildcard-admin check, table + JSON output, CI  ✅
- v0.2  remaining checks in the table above
- v0.3  `--org` mode: assume a role into every account in an AWS Organization
- v0.4  IAM Access Analyzer integration; SARIF output for GitHub code scanning
