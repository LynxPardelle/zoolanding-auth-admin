#!/usr/bin/env python3
"""Materialize fail-closed Auth Admin TEST parameters without logging secrets."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from typing import Mapping


class ParameterPreparationError(ValueError):
    pass


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ParameterPreparationError(f"{name.lower()}_required")
    return value


def _require_json_base64(value: str) -> None:
    try:
        payload = json.loads(base64.b64decode(value, validate=True).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ParameterPreparationError("auth_admin_config_invalid") from exc
    if not isinstance(payload, dict):
        raise ParameterPreparationError("auth_admin_config_invalid")


def build_parameters(env: Mapping[str, str]) -> tuple[dict[str, str], set[str]]:
    if env.get("AUTH_ADMIN_CONFIG_READY") != "true":
        raise ParameterPreparationError("auth_admin_config_not_ready")
    config = _required(env, "AUTH_ADMIN_CONFIG_JSON_BASE64")
    pools = _required(env, "COGNITO_USER_POOL_ARNS")
    _require_json_base64(config)
    for value in pools.split(","):
        if re.fullmatch(r"arn:(?:aws|aws-us-gov|aws-cn):cognito-idp:[a-z0-9-]+:[0-9]{12}:userpool/[A-Za-z0-9_-]+", value.strip()) is None:
            raise ParameterPreparationError("cognito_user_pool_arns_invalid")
    zeros = "0" * 64
    return {
        "EnvironmentName": "test",
        "AuthAdminConfigJsonBase64": config,
        "CognitoUserPoolArns": pools,
        "LogLevel": "INFO",
        "EnableThnAuthAdminV2": "false",
        "ProvisionThnAuthAdminV2State": "false",
        "ThnAuthAdminV2TerminationProtectionGate": "BLOCKED",
        "ThnAuthAdminV2DescriptorVersionId": "BLOCKED",
        "ThnAuthAdminV2DescriptorSha256": zeros,
        "ThnAuthAdminV2AuthPolicyVersion": "BLOCKED",
        "ThnAuthAdminV2OriginHeaderSha256Current": zeros,
        "ThnAuthAdminV2OriginHeaderSha256Previous": zeros,
    }, {"AuthAdminConfigJsonBase64"}


def write_parameter_files(output: Path, parameters: Mapping[str, str], sensitive: set[str]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    if any(not key or not isinstance(value, str) or "\n" in value or "\r" in value for key, value in parameters.items()):
        raise ParameterPreparationError("test_parameter_invalid")
    (output / "parameters.json").write_text(json.dumps([{"ParameterKey": key, "ParameterValue": value} for key, value in parameters.items()], separators=(",", ":")), encoding="utf-8")
    (output / "expected-parameters.txt").write_text("".join(f"{key}={parameters[key]}\n" for key in sorted(parameters) if key not in sensitive), encoding="utf-8")
    (output / "required-parameters.txt").write_text("".join(f"{key}\n" for key in sorted(sensitive) if parameters.get(key)), encoding="utf-8")


def _validate_runtime_config() -> None:
    root = Path(__file__).resolve().parents[1]
    candidates = (root / "AuthAdminFunction" / "lambda_function.py", root / "lambda_function.py")
    handler_path = next((path for path in candidates if path.is_file()), None)
    if handler_path is None:
        raise ParameterPreparationError("auth_admin_runtime_validator_missing")
    spec = importlib.util.spec_from_file_location("auth_admin_release_validator", handler_path)
    if spec is None or spec.loader is None:
        raise ParameterPreparationError("auth_admin_runtime_validator_missing")
    sys.path.insert(0, str(handler_path.parent))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.load_config()


def main() -> int:
    parameters, sensitive = build_parameters(os.environ)
    os.environ["AUTH_ADMIN_ENVIRONMENT"] = "test"
    _validate_runtime_config()
    write_parameter_files(Path(os.environ["RUNNER_TEMP"]) / "test-release-parameters", parameters, sensitive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
