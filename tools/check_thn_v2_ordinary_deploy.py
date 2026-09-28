#!/usr/bin/env python3
"""Block the ordinary TEST deploy whenever THN Auth Admin v2 state may exist."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from typing import Any


STACK_NAME = "zoolanding-auth-admin-test"
AWS_REGION = "us-east-1"
_STABLE_STACK_STATUSES = frozenset(
    {
        "CREATE_COMPLETE",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
    }
)
_DESCRIBE_QUERY = (
    "[Stacks[0].StackStatus, "
    "length(Stacks[0].Parameters[?"
    "(ParameterKey == 'EnableThnAuthAdminV2' || "
    "ParameterKey == 'ProvisionThnAuthAdminV2State') && "
    "ParameterValue != 'false'])]"
)
_RESOURCE_QUERY = (
    "length(StackResourceSummaries[?"
    "starts_with(LogicalResourceId, 'ThnAuthAdminV2') && "
    "ResourceStatus != 'DELETE_COMPLETE'])"
)
_Runner = Callable[..., Any]


class OrdinaryDeployBlocked(RuntimeError):
    """The ordinary deployment must not own the currently active v2 boundary."""


class GuardVerificationError(RuntimeError):
    """The guard could not prove that an ordinary deployment is safe."""


class _AwsQueryError(RuntimeError):
    def __init__(self, stderr: str):
        super().__init__("AWS query failed")
        self.stderr = stderr


def _aws_query(operation: str, query: str, *, runner: _Runner) -> str:
    try:
        completed = runner(
            [
                "aws",
                "cloudformation",
                operation,
                "--stack-name",
                STACK_NAME,
                "--region",
                AWS_REGION,
                "--query",
                query,
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise GuardVerificationError("THN v2 stack state could not be verified") from error
    returncode = getattr(completed, "returncode", None)
    stdout = getattr(completed, "stdout", None)
    stderr = getattr(completed, "stderr", None)
    if type(returncode) is not int or not isinstance(stdout, str) or not isinstance(stderr, str):
        raise GuardVerificationError("THN v2 stack state could not be verified")
    if returncode != 0:
        raise _AwsQueryError(stderr)
    if len(stdout) > 1_024:
        raise GuardVerificationError("THN v2 stack state could not be verified")
    return stdout


def _is_missing_stack(error: _AwsQueryError) -> bool:
    return bool(
        "(ValidationError)" in error.stderr
        and re.search(
            rf"Stack with id\s+{re.escape(STACK_NAME)}\s+does not exist(?:\s|$)",
            error.stderr,
        )
    )


def verify_ordinary_deploy_safe(*, runner: _Runner = subprocess.run) -> None:
    try:
        described = _aws_query("describe-stacks", _DESCRIBE_QUERY, runner=runner)
    except _AwsQueryError as error:
        if _is_missing_stack(error):
            return
        raise GuardVerificationError("THN v2 stack state could not be verified") from None

    try:
        description = json.loads(described)
    except (TypeError, json.JSONDecodeError) as error:
        raise GuardVerificationError("THN v2 stack state could not be verified") from error
    if (
        not isinstance(description, list)
        or len(description) != 2
        or not isinstance(description[0], str)
        or type(description[1]) is not int
        or description[1] < 0
    ):
        raise GuardVerificationError("THN v2 stack state could not be verified")
    stack_status, active_parameter_count = description
    if stack_status not in _STABLE_STACK_STATUSES:
        raise GuardVerificationError("THN v2 stack state could not be verified")
    if active_parameter_count != 0:
        raise OrdinaryDeployBlocked("THN v2 state is active")

    try:
        resources = _aws_query(
            "list-stack-resources",
            _RESOURCE_QUERY,
            runner=runner,
        )
    except _AwsQueryError:
        raise GuardVerificationError("THN v2 stack state could not be verified") from None
    try:
        thn_resource_count = json.loads(resources)
    except (TypeError, json.JSONDecodeError) as error:
        raise GuardVerificationError("THN v2 stack state could not be verified") from error
    if type(thn_resource_count) is not int or thn_resource_count < 0:
        raise GuardVerificationError("THN v2 stack state could not be verified")
    if thn_resource_count != 0:
        raise OrdinaryDeployBlocked("THN v2 state is active")


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: _Runner = subprocess.run,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        print("THN v2 ordinary deploy guard accepts no arguments.", file=sys.stderr)
        return 2
    try:
        verify_ordinary_deploy_safe(runner=runner)
    except OrdinaryDeployBlocked:
        print(
            "Ordinary TEST deployment is blocked; use the dedicated THN v2 workflow.",
            file=sys.stderr,
        )
        return 2
    except GuardVerificationError:
        print(
            "Ordinary TEST deployment is blocked because THN v2 state could not be verified.",
            file=sys.stderr,
        )
        return 2
    print("THN v2 ordinary deploy guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
