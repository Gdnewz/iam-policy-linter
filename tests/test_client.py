"""Integration-style tests against a FAKE AWS, using moto.

moto intercepts boto3 calls and answers from an in-memory model of AWS. So
you can create policies, users and roles, then check the client fetches them —
with no credentials, no network, and no bill.

The @mock_aws decorator is all it takes. Inside it, boto3 talks to moto.
"""

import json

import boto3
import pytest
from moto import mock_aws

from iam_linter import client

ADMIN_DOC = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
READ_DOC = {"Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}


@pytest.fixture
def iam():
    with mock_aws():
        yield boto3.client("iam", region_name="us-east-1")


def test_customer_managed_policies_are_fetched(iam):
    iam.create_policy(PolicyName="AdminLike", PolicyDocument=json.dumps(ADMIN_DOC))
    iam.create_policy(PolicyName="ReadOnlyish", PolicyDocument=json.dumps(READ_DOC))

    policies = client.get_customer_managed_policies(iam)

    assert sorted(p.name for p in policies) == ["AdminLike", "ReadOnlyish"]
    admin = next(p for p in policies if p.name == "AdminLike")
    assert admin.document["Statement"][0]["Action"] == "*"


def test_inline_policies_across_principal_types(iam):
    iam.create_user(UserName="alice")
    iam.put_user_policy(UserName="alice", PolicyName="alice-inline", PolicyDocument=json.dumps(READ_DOC))

    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="Deploy", AssumeRolePolicyDocument=json.dumps(trust))
    iam.put_role_policy(RoleName="Deploy", PolicyName="deploy-inline", PolicyDocument=json.dumps(ADMIN_DOC))

    iam.create_group(GroupName="devs")
    iam.put_group_policy(GroupName="devs", PolicyName="devs-inline", PolicyDocument=json.dumps(READ_DOC))

    policies = client.get_inline_policies(iam)

    assert {p.attached_to for p in policies} == {"user/alice", "role/Deploy", "group/devs"}


@pytest.mark.xfail(raises=NotImplementedError, reason="exercise 3")
def test_mfa_status(iam):
    iam.create_user(UserName="console-user")
    iam.create_login_profile(UserName="console-user", Password="Xx-not-a-real-password-1")
    iam.create_user(UserName="api-only")

    rows = {r["user"]: r for r in client.get_users_with_mfa_status(iam)}

    assert rows["console-user"]["has_console_password"] is True
    assert rows["console-user"]["mfa_enabled"] is False
    assert rows["api-only"]["has_console_password"] is False


@pytest.mark.xfail(raises=NotImplementedError, reason="exercise 4")
def test_access_keys(iam):
    iam.create_user(UserName="bob")
    iam.create_access_key(UserName="bob")

    keys = client.get_access_keys(iam)

    assert len(keys) == 1
    assert keys[0]["user"] == "bob"
    assert keys[0]["status"] == "Active"
