"""Data structures shared across the linter.

Keeping these in one small module means every check returns the same shape,
so the reporter never has to care which check produced a finding.
"""

from dataclasses import dataclass, field


@dataclass
class Policy:
    """One IAM policy document, plus enough context to say where it lives.

    IAM policies come from three places:
      * customer-managed policies  (standalone, attached to users/roles/groups)
      * inline policies            (embedded directly in a user/role/group)
      * AWS-managed policies       (owned by AWS; you can't edit them, so we skip them)

    `document` is the parsed JSON policy document. In IAM, a document looks like:
        {"Version": "2012-10-17", "Statement": [ {...}, {...} ]}
    NOTE: "Statement" may be a single dict OR a list of dicts. Always normalise.
    """

    name: str
    arn: str            # for inline policies we synthesise something readable
    document: dict
    attached_to: str = ""   # e.g. "role/DeployRole" — where the policy is used


@dataclass
class Finding:
    """One problem the linter found.

    severity: "HIGH" | "MEDIUM" | "LOW"
    check:    short id of the check that fired, e.g. "wildcard-admin"
    """

    severity: str
    check: str
    policy_name: str
    resource: str
    message: str
    statement: dict = field(default_factory=dict)  # the offending statement, for context

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "check": self.check,
            "policy_name": self.policy_name,
            "resource": self.resource,
            "message": self.message,
            "statement": self.statement,
        }
