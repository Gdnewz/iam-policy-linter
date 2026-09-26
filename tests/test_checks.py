"""Unit tests for checks. No AWS involved — we build Policy objects by hand.

Run:  pytest -v
Tests marked xfail are the exercises. When you implement a check, remove its
@pytest.mark.xfail line and the test must go green.
"""

import pytest

from iam_linter.checks import (
    check_sensitive_action_without_condition,
    check_service_wildcard,
    check_wildcard_admin,
    run_checks,
)
from iam_linter.models import Policy


def make_policy(*stmts, name="TestPolicy"):
    """Build a Policy from one or more statement dicts."""
    return Policy(name=name, arn=f"arn:aws:iam::123456789012:policy/{name}",
                  document={"Version": "2012-10-17", "Statement": list(stmts)})


ADMIN = {"Effect": "Allow", "Action": "*", "Resource": "*"}
READ_ONE_BUCKET = {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"}


# ------------------------------------------------------------ implemented --

class TestWildcardAdmin:
    def test_flags_full_admin(self):
        findings = check_wildcard_admin(make_policy(ADMIN))
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert findings[0].check == "wildcard-admin"

    def test_ignores_scoped_policy(self):
        assert check_wildcard_admin(make_policy(READ_ONE_BUCKET)) == []

    def test_ignores_deny(self):
        deny_all = {"Effect": "Deny", "Action": "*", "Resource": "*"}
        assert check_wildcard_admin(make_policy(deny_all)) == []

    def test_handles_single_statement_dict(self):
        # IAM allows "Statement": {...} instead of a list. Normalisation must cope.
        policy = Policy(name="p", arn="a", document={"Statement": ADMIN})
        assert len(check_wildcard_admin(policy)) == 1

    def test_action_star_in_list(self):
        stmt = {"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]}
        assert len(check_wildcard_admin(make_policy(stmt))) == 1


def test_run_checks_aggregates():
    policies = [make_policy(ADMIN, name="A"), make_policy(READ_ONE_BUCKET, name="B")]
    findings = run_checks(policies, checks=[check_wildcard_admin])
    assert [f.policy_name for f in findings] == ["A"]


# -------------------------------------------------------------- exercises --


class TestServiceWildcard:
    def test_flags_s3_star_on_all_resources(self):
        stmt = {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        findings = check_service_wildcard(make_policy(stmt))
        assert len(findings) == 1
        assert findings[0].severity == "MEDIUM"

    def test_iam_star_is_high(self):
        stmt = {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
        assert check_service_wildcard(make_policy(stmt))[0].severity == "HIGH"

    def test_ignores_scoped_resource(self):
        stmt = {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::my-bucket"}
        assert check_service_wildcard(make_policy(stmt)) == []


@pytest.mark.xfail(raises=NotImplementedError, reason="exercise 2")
class TestSensitiveActionWithoutCondition:
    def test_flags_passrole_without_condition(self):
        stmt = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}
        findings = check_sensitive_action_without_condition(make_policy(stmt))
        assert len(findings) == 1
        assert "iam:PassRole" in findings[0].message

    def test_allows_passrole_with_condition(self):
        stmt = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
                "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}}
        assert check_sensitive_action_without_condition(make_policy(stmt)) == []

    def test_ignores_harmless_action(self):
        assert check_sensitive_action_without_condition(make_policy(READ_ONE_BUCKET)) == []
