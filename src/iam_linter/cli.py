"""Command-line entry point.

    python -m iam_linter                # table to terminal
    python -m iam_linter --json out.json
    python -m iam_linter --profile dev  # use a named AWS CLI profile

Exit code is 1 when any HIGH finding exists, so this can gate a CI pipeline.
"""

from __future__ import annotations

import argparse
import sys

import boto3

from . import checks, client, report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="iam-linter", description="Lint IAM policies for risky patterns.")
    p.add_argument("--profile", help="AWS CLI profile name")
    p.add_argument("--json", metavar="FILE", help="also write findings as JSON to FILE")
    p.add_argument("--fail-on", default="HIGH", choices=["HIGH", "MEDIUM", "LOW", "NONE"],
                   help="exit 1 if a finding of this severity or worse exists (default HIGH)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    iam = session.client("iam")

    policies = client.get_all_policies(iam)
    findings = checks.run_checks(policies)

    report.print_table(findings)
    if args.json:
        with open(args.json, "w") as fh:
            fh.write(report.to_json(findings))

    if args.fail_on != "NONE":
        threshold = report.SEVERITY_ORDER[args.fail_on]
        if any(report.SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
