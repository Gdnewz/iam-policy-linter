"""Everything that talks to AWS lives here.

Design rule: this module FETCHES and returns plain Python objects. It never
decides whether something is bad. That's the checks' job. Separating "get data"
from "judge data" is what makes the checks trivially unit-testable — you can
hand them a dict and never touch AWS.

boto3 concepts you'll meet here
--------------------------------
* boto3.client("iam")        - low-level client; one method per API call.
* Paginators                 - IAM list_* calls return at most 100 items per
                               call. A paginator handles the "IsTruncated /
                               Marker" loop for you. Always use them.
* get_policy_version         - customer-managed policies are versioned. The
                               document you want is the *default* version.
"""

from __future__ import annotations
from time import timezone
from datetime import datetime, timezone
import boto3

from .models import Finding, Policy


def _as_list(x):
    """IAM lets many fields be a single value OR a list. Normalise to list."""
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def get_customer_managed_policies(iam=None) -> list[Policy]:
    """Return every customer-managed policy with its default document.

    Scope="Local" means "only policies this account created". Without it you
    also get the ~1000 AWS-managed policies, which you can't change anyway.
    """
    iam = iam or boto3.client("iam")
    policies: list[Policy] = []

    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for p in page["Policies"]:
            version = iam.get_policy_version(
                PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"]
            )
            doc = version["PolicyVersion"]["Document"]
            policies.append(
                Policy(
                    name=p["PolicyName"],
                    arn=p["Arn"],
                    document=doc,
                    attached_to=f"{p.get('AttachmentCount', 0)} attachment(s)",
                )
            )
    return policies


def get_inline_policies(iam=None) -> list[Policy]:
    """Return inline policies embedded in users, roles and groups.

    Inline policies have no ARN and no versions. There are three parallel
    families of API calls (user/role/group) that behave identically, so we
    loop over a small table instead of writing the code three times.
    """
    iam = iam or boto3.client("iam")
    policies: list[Policy] = []

    # (list-principals API, key in response, name field, list-policies API, get-policy API, kwarg name)
    kinds = [
        ("list_users",  "Users",  "UserName",  "list_user_policies",  "get_user_policy",  "UserName"),
        ("list_roles",  "Roles",  "RoleName",  "list_role_policies",  "get_role_policy",  "RoleName"),
        ("list_groups", "Groups", "GroupName", "list_group_policies", "get_group_policy", "GroupName"),
    ]

    for list_api, key, name_field, list_pol_api, get_pol_api, kwarg in kinds:
        for page in iam.get_paginator(list_api).paginate():
            for principal in page[key]:
                pname = principal[name_field]
                for pol_page in iam.get_paginator(list_pol_api).paginate(**{kwarg: pname}):
                    for policy_name in pol_page["PolicyNames"]:
                        resp = getattr(iam, get_pol_api)(**{kwarg: pname, "PolicyName": policy_name})
                        label = f"{key[:-1].lower()}/{pname}"   # e.g. role/DeployRole
                        policies.append(
                            Policy(
                                name=policy_name,
                                arn=f"inline:{label}:{policy_name}",
                                document=resp["PolicyDocument"],
                                attached_to=label,
                            )
                        )
    return policies


def get_all_policies(iam=None) -> list[Policy]:
    iam = iam or boto3.client("iam")
    return get_customer_managed_policies(iam) + get_inline_policies(iam)


# ---------------------------------------------------------------------------
# v0.2 — you will implement these. See LEARNING.md, exercise 3 and 4.
# ---------------------------------------------------------------------------

def get_users_with_mfa_status(iam=None) -> list[dict]:
    """Return [{"user": name, "has_console_password": bool, "mfa_enabled": bool}, ...].

    Hints:
      * list_users (paginated) gives you the names.
      * get_login_profile(UserName=...) raises NoSuchEntityException when the
        user has no console password — that's the *expected* way to detect
        "API-only user". Catch iam.exceptions.NoSuchEntityException.
      * list_mfa_devices(UserName=...) returns a list; empty == no MFA.
    """
    iam = iam or boto3.client("iam")
    users = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page["Users"]:
            user_name = u["UserName"]
            try:
                iam.get_login_profile(UserName=user_name)
                has_console_password = True
            except iam.exceptions.NoSuchEntityException:
                has_console_password = False

            mfa_devices = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
            mfa_enabled = bool(mfa_devices)
            users.append({"user": user_name,
                           "has_console_password": has_console_password, 
                           "mfa_enabled": mfa_enabled})
    
    return users

def get_access_keys(iam=None) -> list[dict]:
    """Return [{"user": name, "key_id": id, "status": "Active"|"Inactive", "created": datetime}, ...].

    Hints:
      * list_access_keys(UserName=...) -> "AccessKeyMetadata" list.
      * "CreateDate" is a timezone-aware datetime. Compare with
        datetime.now(timezone.utc), never datetime.now().
    """
    iam = iam or boto3.client("iam")
    access_keys = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page["Users"]:
            user_name = u["UserName"]
            keys_page = iam.list_access_keys(UserName=user_name)
            for key in keys_page["AccessKeyMetadata"]:
                access_keys.append({
                    "user": user_name,
                    "key_id": key["AccessKeyId"],
                    "status": key["Status"],
                    "created": key["CreateDate"]
                })
    return access_keys

def check_stale_access_key(key_rows, now=None) -> list[Finding]:
    """MEDIUM: Access keys older than 90 days.

    Hints:
      * key_rows is the output of get_access_keys().
      * now is a timezone-aware datetime. Compare with key["created"].
    """
   
    findings: list[Finding] = []
    now = now or datetime.now(timezone.utc)
    for key in key_rows:
        age_days = (now - key["created"]).days
        if age_days > 90:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    check="stale-access-key",
                    policy_name="N/A",
                    resource=f"user/{key['user']}",
                    message=f"Access key {key['key_id']} is {age_days} days old.",
                )
            )
    return findings
