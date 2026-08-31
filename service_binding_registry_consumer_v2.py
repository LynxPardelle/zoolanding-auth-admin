"""Fail-closed exact-key reader for the private THN Content Hub v2 registry.

This module is an additive v2 primitive.  Existing Auth Admin v1 handlers do
not import or invoke it.  The authoritative row remains owned by Content Hub;
this consumer performs one strongly consistent read and never persists a copy.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Mapping, NoReturn


APPROVED_TABLE_NAME = "zoolanding-content-hub-test-ServiceBindingRegistryV2"
APPROVED_PARTITION_KEY = "SERVICE_BINDING#test#thn-journal-test-v2"
APPROVED_SORT_KEY = "REGISTRY#V2"

_EXPECTED_DESCRIPTOR_FIELDS = frozenset(
    {"descriptorVersionId", "descriptorSha256", "authPolicyVersion"}
)
_RECORD_FIELDS = frozenset(
    {
        "pk",
        "sk",
        "recordType",
        "schemaVersion",
        "environment",
        "domain",
        "serviceBindingId",
        "descriptorVersionId",
        "descriptorSha256",
        "registryRevision",
        "activationStatus",
        "writerMode",
        "writerEpoch",
        "hubId",
        "tenantId",
        "cookieNamespace",
        "authProfileId",
        "authPolicyVersion",
        "adminOrigin",
        "resourceBindings",
        "reservationOwner",
    }
)
_RESERVATION_OWNER = {
    "environment": "test",
    "domain": "thehairnarrative.com",
    "serviceBindingId": "thn-journal-test-v2",
    "hubId": "thehairnarrative-com-journal",
    "tenantId": "thehairnarrative-com",
    "authProfileId": "journal-owner",
}
_FIXED_RECORD_FIELDS = {
    "pk": APPROVED_PARTITION_KEY,
    "sk": APPROVED_SORT_KEY,
    "recordType": "service-binding-registry-v2",
    "schemaVersion": 2,
    "environment": "test",
    "domain": "thehairnarrative.com",
    "serviceBindingId": "thn-journal-test-v2",
    "activationStatus": "active",
    "hubId": "thehairnarrative-com-journal",
    "tenantId": "thehairnarrative-com",
    "cookieNamespace": "endefiz7dkk635k6di6k",
    "authProfileId": "journal-owner",
    "adminOrigin": "https://admin-test.thehairnarrative.com",
}
_ALLOWED_WRITER_MODES = frozenset({"disabled", "qa-only", "client-owner"})
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]+$")
_INTEGER_RE = re.compile(r"-?[0-9]+")


class RegistryConsumerError(RuntimeError):
    """The authoritative binding cannot safely authorize a v2 consumer."""


# Semantic alias retained for callers that prefer availability terminology.
ServiceBindingUnavailable = RegistryConsumerError


def _reject() -> NoReturn:
    raise RegistryConsumerError("service binding is unavailable")


def marshal_value(value: Any) -> dict[str, Any]:
    """Marshal the narrow registry value contract for a low-level client."""

    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, int):
        return {"N": str(value)}
    if isinstance(value, Mapping):
        return {"M": {str(key): marshal_value(item) for key, item in value.items()}}
    if isinstance(value, (list, tuple)):
        return {"L": [marshal_value(item) for item in value]}
    _reject()


def marshal_item(item: Mapping[str, Any] | None) -> dict[str, Any]:
    if item is None:
        return {}
    if not isinstance(item, Mapping):
        _reject()
    return {str(key): marshal_value(value) for key, value in item.items()}


def unmarshal_value(value: Any) -> Any:
    """Unmarshal only the DynamoDB types admitted by the registry schema."""

    if not isinstance(value, Mapping):
        _reject()
    if set(value) == {"S"} and isinstance(value["S"], str):
        return value["S"]
    if set(value) == {"N"}:
        number = value["N"]
        if not isinstance(number, str) or not _INTEGER_RE.fullmatch(number):
            _reject()
        return int(number)
    if set(value) == {"BOOL"} and type(value["BOOL"]) is bool:
        return value["BOOL"]
    if set(value) == {"M"} and isinstance(value["M"], Mapping):
        return {str(key): unmarshal_value(item) for key, item in value["M"].items()}
    if set(value) == {"L"} and isinstance(value["L"], list):
        return [unmarshal_value(item) for item in value["L"]]
    _reject()


def unmarshal_item(item: Any) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        _reject()
    return {str(key): unmarshal_value(value) for key, value in item.items()}


def _validate_expected_descriptor(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _EXPECTED_DESCRIPTOR_FIELDS:
        _reject()
    descriptor_version = value.get("descriptorVersionId")
    descriptor_sha256 = value.get("descriptorSha256")
    auth_policy_version = value.get("authPolicyVersion")
    if (
        not isinstance(descriptor_version, str)
        or not _SAFE_ID_RE.fullmatch(descriptor_version)
        or not isinstance(descriptor_sha256, str)
        or not _SHA256_RE.fullmatch(descriptor_sha256)
        or not isinstance(auth_policy_version, str)
        or not _SAFE_ID_RE.fullmatch(auth_policy_version)
    ):
        _reject()
    return {
        "descriptorVersionId": descriptor_version,
        "descriptorSha256": descriptor_sha256,
        "authPolicyVersion": auth_policy_version,
    }


def _validate_trusted_resource_scope(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"partition", "accountId", "region"}:
        _reject()
    partition = value.get("partition")
    account_id = value.get("accountId")
    region = value.get("region")
    if (
        partition not in {"aws", "aws-us-gov", "aws-cn"}
        or not isinstance(account_id, str)
        or not _ACCOUNT_ID_RE.fullmatch(account_id)
        or not isinstance(region, str)
        or not _REGION_RE.fullmatch(region)
    ):
        _reject()
    return {"partition": partition, "accountId": account_id, "region": region}


def _expected_resource_bindings(scope: Mapping[str, str]) -> dict[str, str]:
    arn_prefix = f"arn:{scope['partition']}"
    location = f"{scope['region']}:{scope['accountId']}"
    return {
        "authoringFunctionArn": (
            f"{arn_prefix}:lambda:{location}:function:"
            "zoolanding-content-hub-test-ThnContentHubV2Authoring"
        ),
        "metadataTableArn": (
            f"{arn_prefix}:dynamodb:{location}:table/"
            "zoolanding-content-hub-test-ThnContentHubV2Metadata"
        ),
    }


def _validate_record(
    item: Any,
    *,
    expected_descriptor: Mapping[str, str],
    trusted_resource_scope: Mapping[str, str],
) -> dict[str, Any]:
    if not isinstance(item, Mapping) or set(item) != _RECORD_FIELDS:
        _reject()
    if any(item.get(field) != value for field, value in _FIXED_RECORD_FIELDS.items()):
        _reject()
    if any(item.get(field) != value for field, value in expected_descriptor.items()):
        _reject()
    if type(item.get("registryRevision")) is not int or item["registryRevision"] < 1:
        _reject()
    if type(item.get("writerEpoch")) is not int or item["writerEpoch"] < 1:
        _reject()
    if item.get("writerMode") not in _ALLOWED_WRITER_MODES:
        _reject()
    if item.get("reservationOwner") != _RESERVATION_OWNER:
        _reject()
    if item.get("resourceBindings") != _expected_resource_bindings(trusted_resource_scope):
        _reject()
    return deepcopy(dict(item))


def load_active_service_binding(
    dynamodb_client: Any,
    *,
    expected_descriptor: Mapping[str, Any],
    trusted_resource_scope: Mapping[str, Any],
) -> dict[str, Any]:
    """Load and revalidate the single active authoritative THN v2 row.

    Descriptor coordinates must come from immutable server-owned config, not a
    browser request.  The table/key are code-owned and cannot be redirected by
    a caller.  Provider and validation failures deliberately share one safe
    error so private registry contents are never reflected.
    """

    expected = _validate_expected_descriptor(expected_descriptor)
    scope = _validate_trusted_resource_scope(trusted_resource_scope)
    try:
        response = dynamodb_client.get_item(
            TableName=APPROVED_TABLE_NAME,
            Key=marshal_item({"pk": APPROVED_PARTITION_KEY, "sk": APPROVED_SORT_KEY}),
            ConsistentRead=True,
        )
        if not isinstance(response, Mapping) or "Items" in response or "Count" in response:
            _reject()
        raw_item = response.get("Item")
        if not isinstance(raw_item, Mapping) or not raw_item:
            _reject()
        item = unmarshal_item(raw_item)
        return _validate_record(
            item,
            expected_descriptor=expected,
            trusted_resource_scope=scope,
        )
    except RegistryConsumerError:
        raise
    except Exception:
        _reject()


__all__ = [
    "APPROVED_TABLE_NAME",
    "RegistryConsumerError",
    "ServiceBindingUnavailable",
    "load_active_service_binding",
    "marshal_item",
    "unmarshal_item",
]
