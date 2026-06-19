#!/usr/bin/env python3
"""Check auth-admin DynamoDB PITR and audit-table readiness.

The default mode is read-only. Use --enable-pitr only after confirming the
stack/table names are auth-admin tables.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any, Callable


AUTH_ADMIN_TABLE_OUTPUTS = {
    "SessionTableName",
    "UserStateTableName",
    "AuditTableName",
}


AwsRunner = Callable[[list[str]], dict[str, Any]]


def _run_aws(args: list[str], *, region: str) -> dict[str, Any]:
    command = ["aws", *args, "--region", region, "--output", "json"]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout or "{}")


def check_stack(
    stack_name: str,
    region: str,
    *,
    aws: AwsRunner | None = None,
    enable_pitr: bool = False,
) -> dict[str, Any]:
    runner = aws or (lambda args: _run_aws(args, region=region))
    stack = runner(["cloudformation", "describe-stacks", "--stack-name", stack_name])
    outputs = ((stack.get("Stacks") or [{}])[0].get("Outputs") or [])
    table_outputs = [
        output
        for output in outputs
        if output.get("OutputKey") in AUTH_ADMIN_TABLE_OUTPUTS and output.get("OutputValue")
    ]

    tables = [
        check_table(
            output_key=str(output["OutputKey"]),
            table_name=str(output["OutputValue"]),
            region=region,
            stack_name=stack_name,
            aws=runner,
            enable_pitr=enable_pitr,
        )
        for output in table_outputs
    ]
    audit_table_present = any(table["outputKey"] == "AuditTableName" for table in tables)
    return {
        "stackName": stack_name,
        "region": region,
        "ok": bool(tables) and audit_table_present and all(table["pitrEnabled"] for table in tables),
        "auditTablePresent": audit_table_present,
        "tables": tables,
    }


def check_table(
    *,
    output_key: str,
    table_name: str,
    region: str,
    stack_name: str,
    aws: AwsRunner,
    enable_pitr: bool = False,
) -> dict[str, Any]:
    before = aws(["dynamodb", "describe-continuous-backups", "--table-name", table_name])
    before_status = _pitr_status(before)
    update_response: dict[str, Any] | None = None
    after = before

    if before_status != "ENABLED" and enable_pitr:
        if not _is_confirmed_auth_admin_table(stack_name, output_key, table_name):
            raise RuntimeError(f"Refusing to enable PITR for non-auth-admin table: {table_name}")
        update_response = aws([
            "dynamodb",
            "update-continuous-backups",
            "--table-name",
            table_name,
            "--point-in-time-recovery-specification",
            "PointInTimeRecoveryEnabled=true",
        ])
        after = aws(["dynamodb", "describe-continuous-backups", "--table-name", table_name])

    final_status = _pitr_status(after)
    return {
        "outputKey": output_key,
        "tableName": table_name,
        "pitrEnabled": final_status == "ENABLED",
        "initialPointInTimeRecoveryStatus": before_status,
        "finalPointInTimeRecoveryStatus": final_status,
        "continuousBackupsStatus": _continuous_backups_status(after),
        "recoveryPeriodInDays": _recovery_period_days(after),
        "updateResponse": update_response,
    }


def _pitr_status(response: dict[str, Any]) -> str:
    return str(
        ((response.get("ContinuousBackupsDescription") or {})
         .get("PointInTimeRecoveryDescription") or {})
        .get("PointInTimeRecoveryStatus") or "UNKNOWN"
    )


def _continuous_backups_status(response: dict[str, Any]) -> str:
    return str((response.get("ContinuousBackupsDescription") or {}).get("ContinuousBackupsStatus") or "UNKNOWN")


def _recovery_period_days(response: dict[str, Any]) -> int | None:
    value = ((response.get("ContinuousBackupsDescription") or {})
             .get("PointInTimeRecoveryDescription") or {}).get("RecoveryPeriodInDays")
    return int(value) if isinstance(value, int) else None


def _is_confirmed_auth_admin_table(stack_name: str, output_key: str, table_name: str) -> bool:
    return (
        stack_name.startswith("zoolanding-auth-admin-")
        and output_key in AUTH_ADMIN_TABLE_OUTPUTS
        and table_name.startswith(f"{stack_name}-AuthAdmin")
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--stack",
        action="append",
        dest="stacks",
        default=[],
        help="Auth-admin CloudFormation stack name. Repeatable. Defaults to test and prod.",
    )
    parser.add_argument("--enable-pitr", action="store_true", help="Enable PITR for confirmed auth-admin stack tables.")
    args = parser.parse_args(argv)

    stacks = args.stacks or ["zoolanding-auth-admin-test", "zoolanding-auth-admin-prod"]
    report = {
        "ok": True,
        "region": args.region,
        "mode": "enable-pitr" if args.enable_pitr else "read-only",
        "stacks": [],
    }
    for stack_name in stacks:
        stack_report = check_stack(stack_name, args.region, enable_pitr=args.enable_pitr)
        report["stacks"].append(stack_report)
        report["ok"] = bool(report["ok"] and stack_report["ok"])

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
