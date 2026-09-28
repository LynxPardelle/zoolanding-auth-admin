"""Pure, explicit THN TEST selection validation; this module never deploys."""

from __future__ import annotations

import json
import re
from typing import Mapping

from tools.prepare_test_parameters import ParameterPreparationError
from tools.prepare_test_parameters import build_parameters as ordinary_parameters


KEYS = frozenset({
    "EnableThnAuthAdminV2", "ProvisionThnAuthAdminV2State",
    "ThnAuthAdminV2TerminationProtectionGate", "ThnAuthAdminV2DescriptorVersionId",
    "ThnAuthAdminV2DescriptorSha256", "ThnAuthAdminV2AuthPolicyVersion",
    "ThnAuthAdminV2OriginHeaderSha256Current", "ThnAuthAdminV2OriginHeaderSha256Previous",
})
ZERO = "0" * 64


def _invalid() -> None:
    raise ParameterPreparationError("thn_test_selection_invalid")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def parse_selection(raw: str) -> dict[str, str]:
    """Validate a complete selection without loading the shared v1 configuration."""
    if not isinstance(raw, str) or not raw.strip() or len(raw.encode("utf-8")) > 16384:
        _invalid()
    try:
        selection = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, RecursionError):
        _invalid()
    if (not isinstance(selection, dict)
            or set(selection) != {"schemaVersion", "environment", "parameters"}
            or type(selection["schemaVersion"]) is not int
            or selection["schemaVersion"] != 1 or selection["environment"] != "test"):
        _invalid()
    values = selection["parameters"]
    if not isinstance(values, dict) or set(values) != KEYS or any(type(v) is not str for v in values.values()):
        _invalid()
    enabled = values["EnableThnAuthAdminV2"]
    state = values["ProvisionThnAuthAdminV2State"]
    if enabled not in {"true", "false"} or state not in {"true", "false"} or (enabled == "true" and state != "true"):
        _invalid()
    if state == "true" and values["ThnAuthAdminV2TerminationProtectionGate"] != "CONFIRMED_ENABLED":
        _invalid()
    if state == "false" and values["ThnAuthAdminV2TerminationProtectionGate"] not in {"BLOCKED", "CONFIRMED_ENABLED"}:
        _invalid()
    for key in ("ThnAuthAdminV2DescriptorVersionId", "ThnAuthAdminV2AuthPolicyVersion"):
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", values[key]) is None or (enabled == "true" and values[key] == "BLOCKED"):
            _invalid()
    for key in ("ThnAuthAdminV2DescriptorSha256", "ThnAuthAdminV2OriginHeaderSha256Current", "ThnAuthAdminV2OriginHeaderSha256Previous"):
        if re.fullmatch(r"[0-9a-f]{64}", values[key]) is None:
            _invalid()
    current = values["ThnAuthAdminV2OriginHeaderSha256Current"]
    previous = values["ThnAuthAdminV2OriginHeaderSha256Previous"]
    if (enabled == "true" and (current == ZERO or values["ThnAuthAdminV2DescriptorSha256"] == ZERO)) or (current == previous and previous != ZERO):
        _invalid()
    return dict(values)


def build_parameters(env: Mapping[str, str]) -> tuple[dict[str, str], set[str]]:
    values = parse_selection(env.get("THN_V2_TEST_PARAMETERS_JSON", ""))
    if any(env.get(key, "us-east-1") != "us-east-1" for key in ("AWS_REGION", "AWS_DEFAULT_REGION")):
        _invalid()
    if re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+", env.get("AWS_ROLE_ARN", "")) is None:
        _invalid()
    parameters, sensitive = ordinary_parameters(env)
    parameters.update(values)
    sensitive.update({"ThnAuthAdminV2OriginHeaderSha256Current", "ThnAuthAdminV2OriginHeaderSha256Previous"})
    return parameters, sensitive
