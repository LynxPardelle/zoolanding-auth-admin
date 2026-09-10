#!/usr/bin/env python3
"""Isolated, retained-state THN Auth Admin TEST release boundary.

Shared v1 resources and parameter values are preserved from the deployed stack.
This is deliberately separate from the ordinary, v2-disabled deploy path.
"""

from __future__ import annotations

from copy import deepcopy
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import tempfile
import time
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tools.prepare_thn_test_parameters import KEYS, parse_selection
from tools.prepare_test_parameters import ParameterPreparationError
from tools import review_test_change_set as ordinary_review

STACK = "zoolanding-auth-admin-test"
REGION = "us-east-1"
ACCOUNT_HASH = "3e19eeb25ac142d015c5a4d347dc58784b0a79a124f1353b5e92d90673810a8f"
PREFIX = "ThnAuthAdminV2"
ENABLE = "EnableThnAuthAdminV2"
STATE = "ProvisionThnAuthAdminV2State"
GATE = "ThnAuthAdminV2TerminationProtectionGate"
OPERATIONS = frozenset({"provision", "enable", "disable"})
STATE_TYPES = frozenset({"AWS::DynamoDB::Table", "AWS::Cognito::UserPool",
                         "AWS::Cognito::UserPoolClient", "AWS::Cognito::UserPoolGroup",
                         "AWS::Logs::LogGroup"})
# Only these stateless types may disappear when the dedicated runtime is disabled.
PERSISTENT_RUNTIME_TYPES = frozenset({"AWS::Lambda::Function", "AWS::Lambda::Alias",
                                    "AWS::Lambda::ResourcePolicy", "AWS::IAM::Role"})
REMOVABLE_TYPES = frozenset({"AWS::Lambda::Permission", "AWS::Lambda::Url",
    "AWS::IAM::Policy", "AWS::ApiGatewayV2::Api", "AWS::ApiGatewayV2::Stage",
    "AWS::ApiGatewayV2::Deployment", "AWS::ApiGatewayV2::Integration", "AWS::ApiGatewayV2::Route",
    "AWS::ApiGatewayV2::Authorizer", "AWS::CloudWatch::Alarm"})


class ReleaseBlocked(RuntimeError):
    """A sanitized release-boundary failure; never includes provider inputs."""


def _parameters(stack: dict) -> dict[str, str]:
    result = {}
    items = stack.get("Parameters")
    if not isinstance(items, list):
        raise ReleaseBlocked("stack_parameters_invalid")
    for item in items:
        if (not isinstance(item, dict) or not isinstance(item.get("ParameterKey"), str)
                or not isinstance(item.get("ParameterValue"), str) or item["ParameterKey"] in result):
            raise ReleaseBlocked("stack_parameters_invalid")
        result[item["ParameterKey"]] = item["ParameterValue"]
    return result


def validate_stack(stack: Any, account: str, *, expected_account_hash: str = ACCOUNT_HASH) -> None:
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or expected_account_hash == "0" * 64
            or not hmac.compare_digest(hashlib.sha256(account.encode("ascii")).hexdigest(), expected_account_hash)):
        raise ReleaseBlocked("test_account_mismatch")
    expected_arn = rf"arn:aws:cloudformation:{REGION}:{account}:stack/{STACK}/[A-Za-z0-9-]+"
    if (not isinstance(stack, dict) or stack.get("StackName") != STACK
            or re.fullmatch(expected_arn, str(stack.get("StackId", ""))) is None
            or stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}
            or stack.get("EnableTerminationProtection") is not True):
        raise ReleaseBlocked("test_stack_preflight_failed")
    if _parameters(stack).get("EnvironmentName") != "test":
        raise ReleaseBlocked("test_environment_mismatch")


def lifecycle_parameters(stack: dict, operation: str, raw_selection: str | None) -> list[dict]:
    previous = _parameters(stack)
    if operation not in OPERATIONS or previous.get("EnvironmentName") != "test":
        raise ReleaseBlocked("operation_invalid")
    if operation in {"enable", "disable"} and previous.get(STATE) != "true":
        raise ReleaseBlocked("retained_state_required")
    if operation == "provision" and previous.get(ENABLE, "false") != "false":
        raise ReleaseBlocked("provision_cannot_disable_runtime")
    values = {ENABLE: "false", STATE: "true", GATE: "CONFIRMED_ENABLED"}
    if operation == "enable":
        try:
            values = parse_selection(raw_selection or "")
        except ParameterPreparationError:
            raise ReleaseBlocked("thn_test_selection_invalid") from None
        if values[ENABLE] != "true" or values[STATE] != "true":
            raise ReleaseBlocked("enable_selection_required")
    result = [{"ParameterKey": key, "UsePreviousValue": True}
              for key in sorted(previous) if key not in values]
    result.extend({"ParameterKey": key, "ParameterValue": value} for key, value in sorted(values.items()))
    return result


def _thn_key(section: str, key: str) -> bool:
    if section == "Parameters":
        return key in KEYS
    if section == "Conditions":
        return key.startswith("Is" + PREFIX)
    return key.startswith(PREFIX)


def compose_template(candidate: dict, previous: dict, operation: str = "enable") -> dict:
    """Keep v1 byte-equivalent while installing only reviewed, prefixed v2 entries."""
    if operation not in OPERATIONS or not isinstance(candidate, dict) or not isinstance(previous, dict):
        raise ReleaseBlocked("template_invalid")
    if operation == "disable":
        return deepcopy(previous)
    for key in ("Transform", "Globals", "Mappings"):
        if candidate.get(key) != previous.get(key):
            raise ReleaseBlocked("shared_template_drift")
    result = deepcopy(previous)
    for section in ("Resources", "Parameters", "Conditions", "Rules", "Outputs", "Metadata"):
        supplied = candidate.get(section, {})
        current = previous.get(section, {})
        if not isinstance(supplied, dict) or not isinstance(current, dict):
            raise ReleaseBlocked("template_invalid")
        # A retained resource cannot disappear even from the source template.
        for key, value in current.items():
            if (section == "Resources" and _thn_key(section, key)
                    and value.get("Type") in STATE_TYPES and key not in supplied):
                raise ReleaseBlocked("retained_resource_missing")
        combined = {key: deepcopy(value) for key, value in current.items() if not _thn_key(section, key)}
        for key, value in supplied.items():
            if not _thn_key(section, key):
                continue
            if section == "Resources" and value.get("Type") in STATE_TYPES:
                if (value.get("DeletionPolicy") != "Retain" or value.get("UpdateReplacePolicy") != "Retain"
                        or value.get("Condition") != "IsThnAuthAdminV2StateProvisioned"):
                    raise ReleaseBlocked("state_retention_required")
            combined[key] = deepcopy(value)
        if combined:
            result[section] = combined
    return result


def review_resources(changes: Any, operation: str) -> None:
    if operation not in OPERATIONS or not isinstance(changes, list):
        raise ReleaseBlocked("change_set_invalid")
    for change in changes:
        resource = change.get("ResourceChange", {}) if isinstance(change, dict) else {}
        if (not isinstance(change, dict) or change.get("Type") != "Resource" or not isinstance(resource, dict)
                or not str(resource.get("LogicalResourceId", "")).startswith(PREFIX)
                or resource.get("Replacement") not in (None, "False")):
            raise ReleaseBlocked("non_thn_or_replacement_change_forbidden")
        action = resource.get("Action")
        if resource.get("ResourceType") not in STATE_TYPES | PERSISTENT_RUNTIME_TYPES | REMOVABLE_TYPES | {"AWS::Lambda::Version"}:
            raise ReleaseBlocked("resource_type_not_allowlisted")
        if action in {"Add", "Modify"}:
            continue
        if (action == "Remove" and resource.get("ResourceType") == "AWS::Lambda::Version"
                and resource.get("PolicyAction") == "Retain"):
            continue
        if (action == "Remove" and operation == "disable"
                and resource.get("ResourceType") in REMOVABLE_TYPES):
            continue
        raise ReleaseBlocked("resource_removal_forbidden")


def validate_context(env: dict) -> None:
    if (env.get("GITHUB_REPOSITORY") != "LynxPardelle/zoolanding-auth-admin"
            or env.get("GITHUB_REF") != "refs/heads/test"
            or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or not re.fullmatch(r"[a-f0-9]{40}", env.get("GITHUB_SHA", ""))
            or env.get("EXPECTED_SOURCE_SHA") != env.get("GITHUB_SHA")
            or any(not re.fullmatch(r"[1-9][0-9]*", env.get(key, "")) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
            or any(env.get(key) != REGION for key in ("AWS_REGION", "AWS_DEFAULT_REGION"))):
        raise ReleaseBlocked("test_release_context_invalid")


def review_change_set(description: dict, arn: str, name: str, parameters: list[dict], operation: str) -> str:
    """Reuse the ordinary identity checks without relaxing its deletion policy."""
    if (not isinstance(description, dict) or description.get("NextToken")
            or not re.fullmatch(rf"arn:aws:cloudformation:{REGION}:[0-9]{{12}}:changeSet/{re.escape(name)}/[A-Za-z0-9-]+", arn)):
        raise ReleaseBlocked("change_set_identity_invalid")
    changes = description.get("Changes") or []
    review_resources(changes, operation)
    # Ordinary review sees already-checked removal entries as non-replacing updates.
    # Its shared identity, status and parameter validation remains untouched.
    normalized = deepcopy(description)
    for change in normalized.get("Changes") or []:
        if change["ResourceChange"].get("Action") == "Remove":
            change["ResourceChange"]["Action"] = "Modify"
    expected = {p["ParameterKey"]: p["ParameterValue"] for p in parameters if "ParameterValue" in p}
    sensitive = {"ThnAuthAdminV2OriginHeaderSha256Current", "ThnAuthAdminV2OriginHeaderSha256Previous"}
    required = {p["ParameterKey"] for p in parameters}
    expected = {k: v for k, v in expected.items() if k not in sensitive}
    try:
        actual = ordinary_review._parameter_map(description.get("Parameters"))
        if not required.issubset(actual):
            raise ReleaseBlocked("change_set_parameters_missing")
        return ordinary_review.review_change_set(normalized, expected_stack_name=STACK,
            expected_change_set_name=name, expected_change_set_arn=arn, expected_change_set_type="UPDATE",
            expected_parameters=expected, required_parameters=required)
    except ordinary_review.ChangeSetReviewError:
        raise ReleaseBlocked("change_set_review_failed") from None


def _load_template(body: Any) -> dict:
    if isinstance(body, dict):
        return deepcopy(body)
    import yaml
    try:
        result = yaml.safe_load(body)
    except (yaml.YAMLError, TypeError):
        raise ReleaseBlocked("template_decode_failed") from None
    if not isinstance(result, dict):
        raise ReleaseBlocked("template_decode_failed")
    return result


def _inventory(cfn: Any) -> dict[str, dict]:
    result = {}
    token = None
    while True:
        page = cfn.list_stack_resources(StackName=STACK, **({"NextToken": token} if token else {}))
        for item in page.get("StackResourceSummaries", []):
            if item.get("ResourceStatus") == "DELETE_COMPLETE":
                continue
            key = item.get("LogicalResourceId")
            if not isinstance(key, str) or key in result or not item.get("PhysicalResourceId"):
                raise ReleaseBlocked("resource_inventory_invalid")
            result[key] = {k: item.get(k) for k in ("PhysicalResourceId", "ResourceType")}
        token = page.get("NextToken")
        if not token:
            return result


def _package_template(build: Path, bucket: str, prefix: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="thn-package-") as temporary:
        destination = Path(temporary) / "packaged.yaml"
        result = subprocess.run(["sam", "package", "--template-file", str(build / "template.yaml"),
            "--s3-bucket", bucket, "--s3-prefix", prefix, "--region", REGION,
            "--output-template-file", str(destination)], capture_output=True, text=True, check=False)
        if result.returncode:
            raise ReleaseBlocked("artifact_packaging_failed")
        return _load_template(destination.read_text(encoding="utf-8"))


def _verify_retained_state(session: Any, inventory: dict, template: dict) -> None:
    for logical, resource in template.get("Resources", {}).items():
        if not logical.startswith(PREFIX) or resource.get("Type") not in STATE_TYPES:
            continue
        item = inventory.get(logical)
        if not item or item["ResourceType"] != resource["Type"]:
            raise ReleaseBlocked("retained_state_inventory_mismatch")
        resource_type = item["ResourceType"]
        physical = item["PhysicalResourceId"]
        if resource_type == "AWS::DynamoDB::Table":
            client = session.client("dynamodb", region_name=REGION)
            table = client.describe_table(TableName=physical)["Table"]
            backup = client.describe_continuous_backups(TableName=physical)["ContinuousBackupsDescription"]
            if (table.get("TableStatus") != "ACTIVE" or table.get("DeletionProtectionEnabled") is not True
                    or table.get("SSEDescription", {}).get("Status") != "ENABLED"
                    or backup.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus") != "ENABLED"):
                raise ReleaseBlocked("retained_table_protection_mismatch")
        elif resource_type == "AWS::Cognito::UserPool":
            pool = session.client("cognito-idp", region_name=REGION).describe_user_pool(UserPoolId=physical)["UserPool"]
            if pool.get("DeletionProtection") != "ACTIVE" or pool.get("MfaConfiguration") != "ON":
                raise ReleaseBlocked("retained_pool_protection_mismatch")


def run_release(session: Any, env: dict, build: Path, operation: str) -> dict:
    """Run a TEST-only update; the caller must first verify the immutable artifact."""
    validate_context(env)
    if operation not in OPERATIONS or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", env.get("ARTIFACTS_BUCKET", "")):
        raise ReleaseBlocked("release_inputs_invalid")
    identity = session.client("sts", region_name=REGION).get_caller_identity()
    cfn = session.client("cloudformation", region_name=REGION)
    before = cfn.describe_stacks(StackName=STACK)["Stacks"][0]
    validate_stack(before, identity["Account"], expected_account_hash=ACCOUNT_HASH)
    parameters = lifecycle_parameters(before, operation, env.get("THN_V2_TEST_PARAMETERS_JSON"))
    previous = _load_template(cfn.get_template(StackName=STACK, TemplateStage="Original")["TemplateBody"])
    initial_inventory = _inventory(cfn)
    if operation in {"enable", "disable"}:
        _verify_retained_state(session, initial_inventory, previous)
    prefix = f"{STACK}/thn/{env['GITHUB_RUN_ID']}/{env['GITHUB_RUN_ATTEMPT']}/{env['GITHUB_SHA']}"
    candidate = previous if operation == "disable" else _package_template(build, env["ARTIFACTS_BUCKET"], prefix)
    template = compose_template(candidate, previous, operation)
    serialized = json.dumps(template, sort_keys=True, separators=(",", ":")).encode()
    key = prefix + "/template-" + hashlib.sha256(serialized).hexdigest() + ".json"
    session.client("s3", region_name=REGION).put_object(Bucket=env["ARTIFACTS_BUCKET"], Key=key,
        Body=serialized, ContentType="application/json", ServerSideEncryption="AES256",
        ExpectedBucketOwner=identity["Account"])
    name = f"thn-{env['GITHUB_RUN_ID']}-{env['GITHUB_RUN_ATTEMPT']}"
    arguments = {"StackName": STACK, "ChangeSetName": name, "ChangeSetType": "UPDATE",
        "TemplateURL": f"https://s3.{REGION}.amazonaws.com/{env['ARTIFACTS_BUCKET']}/{key}",
        "Parameters": parameters, "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        "Description": f"THN TEST {operation} source {env['GITHUB_SHA']}", "ClientToken": name}
    if before.get("RoleARN"):
        arguments["RoleARN"] = before["RoleARN"]
    change_id = cfn.create_change_set(**arguments)["Id"]
    executed = False
    try:
        for attempt in range(120):
            description = cfn.describe_change_set(StackName=STACK, ChangeSetName=change_id)
            if description.get("Status") not in {"CREATE_PENDING", "CREATE_IN_PROGRESS"}:
                break
            time.sleep(5)
        else:
            raise ReleaseBlocked("change_set_creation_timeout")
        decision = review_change_set(description, change_id, name, parameters, operation)
        if decision == "noop":
            _verify_retained_state(session, initial_inventory, template)
            return {"operation": operation, "decision": "noop", "retained_state_verified": True}
        current = cfn.describe_stacks(StackName=STACK)["Stacks"][0]
        validate_stack(current, identity["Account"], expected_account_hash=ACCOUNT_HASH)
        if (_parameters(current) != _parameters(before) or _inventory(cfn) != initial_inventory
                or _load_template(cfn.get_template(StackName=STACK, TemplateStage="Original")["TemplateBody"]) != previous):
            raise ReleaseBlocked("stack_changed_during_review")
        cfn.execute_change_set(StackName=STACK, ChangeSetName=change_id, ClientRequestToken=name)
        executed = True
        cfn.get_waiter("stack_update_complete").wait(StackName=STACK, WaiterConfig={"Delay": 10, "MaxAttempts": 180})
        for observation in range(2):
            if observation:
                time.sleep(5)
            after = cfn.describe_stacks(StackName=STACK)["Stacks"][0]
            validate_stack(after, identity["Account"], expected_account_hash=ACCOUNT_HASH)
            actual = _parameters(after)
            for parameter in parameters:
                key_name = parameter["ParameterKey"]
                expected = parameter.get("ParameterValue", _parameters(before).get(key_name))
                if key_name not in {"ThnAuthAdminV2OriginHeaderSha256Current", "ThnAuthAdminV2OriginHeaderSha256Previous"} and actual.get(key_name) != expected:
                    raise ReleaseBlocked("deployed_parameter_mismatch")
            inventory = _inventory(cfn)
            for logical, item in initial_inventory.items():
                if (not logical.startswith(PREFIX) or item["ResourceType"] in STATE_TYPES | PERSISTENT_RUNTIME_TYPES) and inventory.get(logical) != item:
                    raise ReleaseBlocked("retained_or_legacy_resource_changed")
            if operation in {"provision", "disable"} and any(item["ResourceType"] in {"AWS::ApiGatewayV2::Api", "AWS::Lambda::Url", "AWS::ApiGatewayV2::Route"}
                    for logical, item in inventory.items() if logical.startswith(PREFIX)):
                raise ReleaseBlocked("disabled_routes_still_present")
            _verify_retained_state(session, inventory, template)
        return {"operation": operation, "decision": "executed", "retained_state_verified": True,
                "source_sha": env["GITHUB_SHA"], "template_sha256": hashlib.sha256(serialized).hexdigest()}
    finally:
        if not executed:
            cfn.delete_change_set(StackName=STACK, ChangeSetName=change_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation", choices=sorted(OPERATIONS), required=True)
    parser.add_argument("--build", type=Path, default=Path(".aws-sam/build"))
    args = parser.parse_args()
    try:
        import boto3
        result = run_release(boto3.Session(region_name=REGION), dict(os.environ), args.build, args.operation)
    except ReleaseBlocked as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        # AWS exceptions can contain parameter values and resource identifiers.
        print("thn_test_release_failed; access remains subject to the independent registry gate", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
