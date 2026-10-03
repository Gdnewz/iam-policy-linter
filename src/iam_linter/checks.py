"""The checks. Each one is a pure function: Policy in, list[Finding] out.

No AWS calls happen here. That's deliberate — you can test every check with a
hand-written dict in milliseconds, and you can reason about the logic without
network noise.

How IAM policy evaluation works (the part that matters for these checks)
-------------------------------------------------------------------------
* Everything is denied by default.
* An "Allow" statement grants access; an explicit "Deny" always wins.
* "Action": "*" means every API call in every service.
* "Resource": "*" means every resource.
* Allow + Action:* + Resource:* with no Condition == full admin. That's the
  single most dangerous statement that can exist, and it's the first check.
* "Condition" narrows a statement (by IP, MFA, tag, time, ...). A sensitive
  action with no Condition is broader than it probably needs to be.
"""

from __future__ import annotations

from .models import Finding, Policy

import boto3

# ----------------------------------------------------------------- helpers --

def statements(policy: Policy) -> list[dict]:
    """Return the policy's statements as a list, whatever shape IAM gave us."""
    stmt = policy.document.get("Statement", [])
    return stmt if isinstance(stmt, list) else [stmt]


def _as_list(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def actions_of(stmt: dict) -> list[str]:
    return _as_list(stmt.get("Action"))


def resources_of(stmt: dict) -> list[str]:
    return _as_list(stmt.get("Resource"))


def is_allow(stmt: dict) -> bool:
    # "Effect" is required by IAM, but be defensive — .get avoids a KeyError.
    return stmt.get("Effect") == "Allow"


# ------------------------------------------------------------------ checks --

def check_wildcard_admin(policy: Policy) -> list[Finding]:
    """HIGH: Allow + Action "*" + Resource "*"  (full administrator access).

    This one is fully implemented. Read it, then run the tests, then break it
    on purpose (change "*" to "**") and watch the test fail. That loop —
    read, run, break, fix — is how you learn a codebase.
    """
    findings: list[Finding] = []
    for stmt in statements(policy):
        if not is_allow(stmt):
            continue
        if "*" in actions_of(stmt) and "*" in resources_of(stmt):
            findings.append(
                Finding(
                    severity="HIGH",
                    check="wildcard-admin",
                    policy_name=policy.name,
                    resource=policy.attached_to or policy.arn,
                    message='Statement allows Action "*" on Resource "*" (full admin).',
                    statement=stmt,
                )
            )
    return findings


def check_service_wildcard(policy: Policy) -> list[Finding]:
    """MEDIUM: Allow with a service-level wildcard, e.g. "s3:*" or "iam:*", on Resource "*".

    Exercise 1. Hints:
      * an action is a service wildcard when it ends with ":*"  ->  act.endswith(":*")
      * "iam:*" and "sts:*" deserve HIGH, not MEDIUM (they let you grant
        yourself anything). Everything else is MEDIUM.
      * Only flag when Resource contains "*" — "s3:*" on one specific bucket
        is a much smaller problem.
    """
    findings: list[Finding] = []
    for stmt in statements(policy):
        if not is_allow(stmt):
            continue
        for action in actions_of(stmt):
            if action.endswith(":*") and "*" in resources_of(stmt):
                severity = "HIGH" if action.split(":")[0] in ("iam", "sts") else "MEDIUM"
                findings.append(
                    Finding(
                        severity=severity,
                        check="service-wildcard",
                        policy_name=policy.name,
                        resource=policy.attached_to or policy.arn,
                        message=f'Statement allows Action "{action}" on Resource "*" (service-level wildcard).',
                        statement=stmt,
                    )
                )
    return findings


# Actions that should basically never be allowed without a Condition.
SENSITIVE_ACTIONS = {
    "iam:PassRole",            # lets you hand a role's powers to a service
    "iam:CreateAccessKey",     # mint credentials for other users
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "sts:AssumeRole",          # become another identity
    "kms:Decrypt",
    "secretsmanager:GetSecretValue",
    "ec2:AuthorizeSecurityGroupIngress",
    "cloudtrail:StopLogging",  # turn off the audit log
    "cloudtrail:DeleteTrail",
}


def check_sensitive_action_without_condition(policy: Policy) -> list[Finding]:
    """MEDIUM: a sensitive action allowed with no Condition block.

    Exercise 2. Hints:
      * stmt.get("Condition") is falsy when absent.
      * Match actions against SENSITIVE_ACTIONS exactly first. Stretch goal:
        also treat "iam:*" and "*" as covering every sensitive action
        (fnmatch.fnmatch(action_name, pattern) does glob matching for you).
      * Put the matched action name in the message so the reader knows
        which one fired.
    """
    findings: list[Finding] = []
    for stmt in statements(policy):
        if not is_allow(stmt):
            continue
        for action in actions_of(stmt):
            if action not in SENSITIVE_ACTIONS:
                continue
            if stmt.get("Condition") is None:
                severity = "MEDIUM"
                message = f'Statement allows sensitive Action "{action}" without a Condition.'
                findings.append(
                    Finding(
                        severity=severity,
                        check="sensitive-no-condition",
                        policy_name=policy.name,
                        resource=policy.attached_to or policy.arn,
                        message=message,
                        statement=stmt,
                    )
                )
    return findings
    
def check_no_mfa_users(users: list[dict]) -> list[Finding]:
    """MEDIUM: Users without MFA enabled.

    Exercise 3. Hints:
      * Each user dict has "user" and "mfa_enabled" keys.
      * The resource string should be the username, e.g. "user/alice".
    """
    findings: list[Finding] = []
    for user in users:
        if not user.get("mfa_enabled"):
            findings.append(
                Finding(
                    severity="MEDIUM",
                    check="no-mfa",
                    policy_name="N/A",
                    resource=f"user/{user.get('user')}",
                    message=f'User "{user.get("user")}" does not have MFA enabled.',
                )
            )
    return findings

# Registry: the CLI runs everything in this list. Add a check here to enable it.
ALL_CHECKS = [
    check_wildcard_admin,
    check_service_wildcard,                     # uncomment after exercise 1
    check_sensitive_action_without_condition,   # uncomment after exercise 2
    check_no_mfa_users,                         # uncomment after exercise 3
]


def run_checks(policies: list[Policy], checks=None) -> list[Finding]:
    checks = checks or ALL_CHECKS
    findings: list[Finding] = []
    for policy in policies:
        for check in checks:
            findings.extend(check(policy))
    return findings
