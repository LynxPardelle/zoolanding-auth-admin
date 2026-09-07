"""Dormant Auth Admin current-user state contract for THN Content Hub v2.

The existing v1 handler deliberately does not import this module.  It is a
closed, TEST-only persistence primitive for the later dedicated Auth Admin v2
stack: purpose is assigned only by create-only provisioning and disablement
can only preserve that purpose while advancing the session version once.
"""

from __future__ import annotations

import re
from copy import deepcopy
from types import MappingProxyType
from typing import Any, Mapping, NoReturn


APPROVED_TABLE_NAME = "zoolanding-auth-admin-test-ThnCurrentUserStateV2"
APPROVED_PARTITION_KEY = "CURRENT_USER#test#thn-journal-test-v2"
APPROVED_OWNER_BINDING_SORT_KEY = "OWNER#client-owner"
APPROVED_SCOPE = MappingProxyType({
    "environment": "test",
    "domain": "thehairnarrative.com",
    "tenantId": "thehairnarrative-com",
    "hubId": "thehairnarrative-com-journal",
    "authProfileId": "journal-owner",
    "serviceBindingId": "thn-journal-test-v2",
})

_STATE_FIELDS = frozenset(
    {
        "contractVersion",
        "scope",
        "subject",
        "accountPurpose",
        "sessionVersion",
        "enabled",
    }
)
_STORAGE_FIELDS = _STATE_FIELDS | {"pk", "sk"}
_OWNER_BINDING_FIELDS = frozenset(
    {
        "contractVersion",
        "scope",
        "subject",
        "accountPurpose",
    }
)
_OWNER_BINDING_STORAGE_FIELDS = _OWNER_BINDING_FIELDS | {"pk", "sk"}
_ACCOUNT_PURPOSES = frozenset({"qa", "client-owner"})
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$")
_INTEGER_RE = re.compile(r"0|[1-9][0-9]*")


class CurrentUserStateUnavailable(RuntimeError):
    """The current-user record cannot safely authorize a v2 operation."""


class CurrentUserSessionStale(CurrentUserStateUnavailable):
    """The authoritative state is available but no longer matches the session."""


def _reject() -> NoReturn:
    raise CurrentUserStateUnavailable("current user state is unavailable") from None


def _validate_scope(value: Any) -> dict[str, str]:
    if (
        not isinstance(value, Mapping)
        or set(value) != set(APPROVED_SCOPE)
        or any(value.get(field) != expected for field, expected in APPROVED_SCOPE.items())
    ):
        _reject()
    return deepcopy(dict(APPROVED_SCOPE))


def _validate_subject(value: Any) -> str:
    if not isinstance(value, str) or not _SUBJECT_RE.fullmatch(value):
        _reject()
    return value


def _validate_account_purpose(value: Any) -> str:
    if not isinstance(value, str) or value not in _ACCOUNT_PURPOSES:
        _reject()
    return value


def _validate_session_version(value: Any) -> int:
    if type(value) is not int or value < 1:
        _reject()
    return value


def _validate_state(
    value: Any,
    *,
    expected_scope: Mapping[str, str],
    expected_subject: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _STATE_FIELDS:
        _reject()
    if type(value.get("contractVersion")) is not int or value["contractVersion"] != 1:
        _reject()
    scope = _validate_scope(value.get("scope"))
    if scope != dict(expected_scope):
        _reject()
    subject = _validate_subject(value.get("subject"))
    if subject != expected_subject:
        _reject()
    purpose = _validate_account_purpose(value.get("accountPurpose"))
    version = _validate_session_version(value.get("sessionVersion"))
    enabled = value.get("enabled")
    if type(enabled) is not bool:
        _reject()
    return {
        "contractVersion": 1,
        "scope": scope,
        "subject": subject,
        "accountPurpose": purpose,
        "sessionVersion": version,
        "enabled": enabled,
    }


def _validate_single_owner_binding(
    value: Any,
    *,
    expected_scope: Mapping[str, str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _OWNER_BINDING_FIELDS:
        _reject()
    if type(value.get("contractVersion")) is not int or value["contractVersion"] != 1:
        _reject()
    scope = _validate_scope(value.get("scope"))
    if scope != dict(expected_scope):
        _reject()
    subject = _validate_subject(value.get("subject"))
    purpose = _validate_account_purpose(value.get("accountPurpose"))
    if purpose != "client-owner":
        _reject()
    return {
        "contractVersion": 1,
        "scope": scope,
        "subject": subject,
        "accountPurpose": purpose,
    }


def _sort_key(subject: str) -> str:
    return f"SUBJECT#{subject}"


def _storage_item(state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "pk": APPROVED_PARTITION_KEY,
        "sk": _sort_key(str(state["subject"])),
        **deepcopy(dict(state)),
    }


def _single_owner_binding_storage_item(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "pk": APPROVED_PARTITION_KEY,
        "sk": APPROVED_OWNER_BINDING_SORT_KEY,
        **deepcopy(dict(binding)),
    }


def _state_from_storage_item(
    value: Any,
    *,
    expected_scope: Mapping[str, str],
    expected_subject: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _STORAGE_FIELDS:
        _reject()
    if value.get("pk") != APPROVED_PARTITION_KEY or value.get("sk") != _sort_key(expected_subject):
        _reject()
    state = {field: value[field] for field in _STATE_FIELDS}
    return _validate_state(
        state,
        expected_scope=expected_scope,
        expected_subject=expected_subject,
    )


def _single_owner_binding_from_storage_item(
    value: Any,
    *,
    expected_scope: Mapping[str, str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _OWNER_BINDING_STORAGE_FIELDS:
        _reject()
    if (
        value.get("pk") != APPROVED_PARTITION_KEY
        or value.get("sk") != APPROVED_OWNER_BINDING_SORT_KEY
    ):
        _reject()
    binding = {field: value[field] for field in _OWNER_BINDING_FIELDS}
    return _validate_single_owner_binding(binding, expected_scope=expected_scope)


def marshal_value(value: Any) -> dict[str, Any]:
    """Marshal the deliberately narrow current-user DynamoDB value set."""

    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, int):
        return {"N": str(value)}
    if isinstance(value, Mapping):
        return {"M": {str(key): marshal_value(item) for key, item in value.items()}}
    _reject()


def marshal_item(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _reject()
    return {str(key): marshal_value(item) for key, item in value.items()}


def unmarshal_value(value: Any) -> Any:
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
    _reject()


def unmarshal_item(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _reject()
    return {str(key): unmarshal_value(item) for key, item in value.items()}


def load_single_owner_binding(
    dynamodb_client: Any,
    *,
    scope: Mapping[str, Any],
) -> dict[str, Any]:
    """Load the exact durable reservation for the sole client owner."""

    trusted_scope = _validate_scope(scope)
    try:
        response = dynamodb_client.get_item(
            TableName=APPROVED_TABLE_NAME,
            Key=marshal_item(
                {
                    "pk": APPROVED_PARTITION_KEY,
                    "sk": APPROVED_OWNER_BINDING_SORT_KEY,
                }
            ),
            ConsistentRead=True,
        )
        if not isinstance(response, Mapping) or "Items" in response or "Count" in response:
            _reject()
        raw_item = response.get("Item")
        if not isinstance(raw_item, Mapping) or not raw_item:
            _reject()
        return _single_owner_binding_from_storage_item(
            unmarshal_item(raw_item),
            expected_scope=trusted_scope,
        )
    except CurrentUserStateUnavailable:
        raise
    except Exception:
        _reject()


def provision_single_owner_state(
    dynamodb_client: Any,
    *,
    scope: Mapping[str, Any],
    subject: str,
    account_purpose: str,
) -> dict[str, Any]:
    """Atomically reserve and create the sole immutable client-owner state."""

    trusted_scope = _validate_scope(scope)
    trusted_subject = _validate_subject(subject)
    trusted_purpose = _validate_account_purpose(account_purpose)
    if trusted_purpose != "client-owner":
        _reject()

    binding = {
        "contractVersion": 1,
        "scope": deepcopy(trusted_scope),
        "subject": trusted_subject,
        "accountPurpose": trusted_purpose,
    }
    state = {
        **deepcopy(binding),
        "sessionVersion": 1,
        "enabled": False,
    }
    condition = "attribute_not_exists(#pk) AND attribute_not_exists(#sk)"
    names = {"#pk": "pk", "#sk": "sk"}

    try:
        dynamodb_client.transact_write_items(
            TransactItems=[
                {
                    "Put": {
                        "TableName": APPROVED_TABLE_NAME,
                        "Item": marshal_item(
                            _single_owner_binding_storage_item(binding)
                        ),
                        "ConditionExpression": condition,
                        "ExpressionAttributeNames": names,
                        "ReturnValuesOnConditionCheckFailure": "NONE",
                    }
                },
                {
                    "Put": {
                        "TableName": APPROVED_TABLE_NAME,
                        "Item": marshal_item(_storage_item(state)),
                        "ConditionExpression": condition,
                        "ExpressionAttributeNames": names,
                        "ReturnValuesOnConditionCheckFailure": "NONE",
                    }
                },
            ],
            ReturnConsumedCapacity="NONE",
            ReturnItemCollectionMetrics="NONE",
        )
        return deepcopy(state)
    except CurrentUserStateUnavailable:
        raise
    except Exception:
        # DynamoDB may have committed the transaction even if its response was
        # lost.  Only the exact initial reservation and state make that retry
        # idempotent; any drift remains a fail-closed conflict.
        existing_binding = load_single_owner_binding(
            dynamodb_client,
            scope=trusted_scope,
        )
        if existing_binding != binding:
            _reject()
        existing_state = load_current_user_state(
            dynamodb_client,
            scope=trusted_scope,
            subject=trusted_subject,
        )
        if existing_state != state:
            _reject()
        return deepcopy(state)


def provision_current_user_state(
    dynamodb_client: Any,
    *,
    scope: Mapping[str, Any],
    subject: str,
    account_purpose: str,
) -> dict[str, Any]:
    """Create one disabled state row; purpose cannot be overwritten later."""

    trusted_scope = _validate_scope(scope)
    trusted_subject = _validate_subject(subject)
    trusted_purpose = _validate_account_purpose(account_purpose)
    state = {
        "contractVersion": 1,
        "scope": trusted_scope,
        "subject": trusted_subject,
        "accountPurpose": trusted_purpose,
        "sessionVersion": 1,
        "enabled": False,
    }
    try:
        dynamodb_client.put_item(
            TableName=APPROVED_TABLE_NAME,
            Item=marshal_item(_storage_item(state)),
            ConditionExpression="attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
            ExpressionAttributeNames={"#pk": "pk", "#sk": "sk"},
            ReturnValues="NONE",
            ReturnValuesOnConditionCheckFailure="NONE",
        )
    except CurrentUserStateUnavailable:
        raise
    except Exception:
        _reject()
    return deepcopy(state)


def load_current_user_state(
    dynamodb_client: Any,
    *,
    scope: Mapping[str, Any],
    subject: str,
) -> dict[str, Any]:
    """Load one exact state row with a strongly consistent read."""

    trusted_scope = _validate_scope(scope)
    trusted_subject = _validate_subject(subject)
    try:
        response = dynamodb_client.get_item(
            TableName=APPROVED_TABLE_NAME,
            Key=marshal_item(
                {"pk": APPROVED_PARTITION_KEY, "sk": _sort_key(trusted_subject)}
            ),
            ConsistentRead=True,
        )
        if not isinstance(response, Mapping) or "Items" in response or "Count" in response:
            _reject()
        raw_item = response.get("Item")
        if not isinstance(raw_item, Mapping) or not raw_item:
            _reject()
        return _state_from_storage_item(
            unmarshal_item(raw_item),
            expected_scope=trusted_scope,
            expected_subject=trusted_subject,
        )
    except CurrentUserStateUnavailable:
        raise
    except Exception:
        _reject()


def disable_current_user_state(
    dynamodb_client: Any,
    *,
    scope: Mapping[str, Any],
    subject: str,
    account_purpose: str,
    session_version: int,
) -> dict[str, Any]:
    """Disable an active row once while preserving purpose and advancing CAS."""

    trusted_scope = _validate_scope(scope)
    trusted_subject = _validate_subject(subject)
    trusted_purpose = _validate_account_purpose(account_purpose)
    trusted_version = _validate_session_version(session_version)
    current = load_current_user_state(
        dynamodb_client,
        scope=trusted_scope,
        subject=trusted_subject,
    )
    if (
        current["accountPurpose"] != trusted_purpose
        or current["sessionVersion"] != trusted_version
        or current["enabled"] is not True
    ):
        _reject()

    expected = deepcopy(current)
    expected["enabled"] = False
    expected["sessionVersion"] = trusted_version + 1
    try:
        response = dynamodb_client.update_item(
            TableName=APPROVED_TABLE_NAME,
            Key=marshal_item(
                {"pk": APPROVED_PARTITION_KEY, "sk": _sort_key(trusted_subject)}
            ),
            ConditionExpression=(
                "#accountPurpose = :expectedPurpose AND "
                "#sessionVersion = :expectedVersion AND #enabled = :expectedEnabled"
            ),
            UpdateExpression="SET #enabled = :disabled, #sessionVersion = :nextVersion",
            ExpressionAttributeNames={
                "#accountPurpose": "accountPurpose",
                "#sessionVersion": "sessionVersion",
                "#enabled": "enabled",
            },
            ExpressionAttributeValues=marshal_item(
                {
                    ":expectedPurpose": trusted_purpose,
                    ":expectedVersion": trusted_version,
                    ":expectedEnabled": True,
                    ":disabled": False,
                    ":nextVersion": trusted_version + 1,
                }
            ),
            ReturnValues="ALL_NEW",
            ReturnValuesOnConditionCheckFailure="NONE",
        )
        if not isinstance(response, Mapping):
            _reject()
        raw_item = response.get("Attributes")
        if not isinstance(raw_item, Mapping) or not raw_item:
            _reject()
        updated = _state_from_storage_item(
            unmarshal_item(raw_item),
            expected_scope=trusted_scope,
            expected_subject=trusted_subject,
        )
        if updated != expected:
            _reject()
        return updated
    except CurrentUserStateUnavailable:
        raise
    except Exception:
        _reject()


def _transition_current_user_state(
    dynamodb_client: Any,
    *,
    scope: Mapping[str, Any],
    subject: str,
    account_purpose: str,
    session_version: int,
    expected_enabled: bool,
    next_enabled: bool,
) -> dict[str, Any]:
    """Advance one exact state version while preserving its immutable purpose."""

    trusted_scope = _validate_scope(scope)
    trusted_subject = _validate_subject(subject)
    trusted_purpose = _validate_account_purpose(account_purpose)
    trusted_version = _validate_session_version(session_version)
    if type(expected_enabled) is not bool or type(next_enabled) is not bool:
        _reject()
    current = load_current_user_state(
        dynamodb_client,
        scope=trusted_scope,
        subject=trusted_subject,
    )
    if (
        current["accountPurpose"] != trusted_purpose
        or current["sessionVersion"] != trusted_version
        or current["enabled"] is not expected_enabled
    ):
        _reject()

    expected = deepcopy(current)
    expected["enabled"] = next_enabled
    expected["sessionVersion"] = trusted_version + 1
    try:
        response = dynamodb_client.update_item(
            TableName=APPROVED_TABLE_NAME,
            Key=marshal_item(
                {"pk": APPROVED_PARTITION_KEY, "sk": _sort_key(trusted_subject)}
            ),
            ConditionExpression=(
                "#accountPurpose = :expectedPurpose AND "
                "#sessionVersion = :expectedVersion AND #enabled = :expectedEnabled"
            ),
            UpdateExpression="SET #enabled = :nextEnabled, #sessionVersion = :nextVersion",
            ExpressionAttributeNames={
                "#accountPurpose": "accountPurpose",
                "#sessionVersion": "sessionVersion",
                "#enabled": "enabled",
            },
            ExpressionAttributeValues=marshal_item(
                {
                    ":expectedPurpose": trusted_purpose,
                    ":expectedVersion": trusted_version,
                    ":expectedEnabled": expected_enabled,
                    ":nextEnabled": next_enabled,
                    ":nextVersion": trusted_version + 1,
                }
            ),
            ReturnValues="ALL_NEW",
            ReturnValuesOnConditionCheckFailure="NONE",
        )
        if not isinstance(response, Mapping):
            _reject()
        raw_item = response.get("Attributes")
        if not isinstance(raw_item, Mapping) or not raw_item:
            _reject()
        updated = _state_from_storage_item(
            unmarshal_item(raw_item),
            expected_scope=trusted_scope,
            expected_subject=trusted_subject,
        )
        if updated != expected:
            _reject()
        return updated
    except CurrentUserStateUnavailable:
        raise
    except Exception:
        _reject()


def enable_current_user_state(
    dynamodb_client: Any,
    *,
    scope: Mapping[str, Any],
    subject: str,
    account_purpose: str,
    session_version: int,
) -> dict[str, Any]:
    """Enable one provisioned account and revoke any pre-activation session."""

    return _transition_current_user_state(
        dynamodb_client,
        scope=scope,
        subject=subject,
        account_purpose=account_purpose,
        session_version=session_version,
        expected_enabled=False,
        next_enabled=True,
    )


def repair_current_user_session_version(
    dynamodb_client: Any,
    *,
    scope: Mapping[str, Any],
    subject: str,
    account_purpose: str,
    session_version: int,
    enabled: bool,
) -> dict[str, Any]:
    """Conditionally revoke sessions without changing purpose or account state."""

    return _transition_current_user_state(
        dynamodb_client,
        scope=scope,
        subject=subject,
        account_purpose=account_purpose,
        session_version=session_version,
        expected_enabled=enabled,
        next_enabled=enabled,
    )


def assert_session_current(
    dynamodb_client: Any,
    *,
    scope: Mapping[str, Any],
    subject: str,
    account_purpose: str,
    session_version: int,
) -> dict[str, Any]:
    """Require an active state matching every explicit private session claim."""

    trusted_scope = _validate_scope(scope)
    trusted_subject = _validate_subject(subject)
    trusted_purpose = _validate_account_purpose(account_purpose)
    trusted_version = _validate_session_version(session_version)
    state = load_current_user_state(
        dynamodb_client,
        scope=trusted_scope,
        subject=trusted_subject,
    )
    if (
        state["enabled"] is not True
        or state["accountPurpose"] != trusted_purpose
        or state["sessionVersion"] != trusted_version
    ):
        raise CurrentUserSessionStale("current user state is unavailable") from None
    return state


__all__ = [
    "APPROVED_OWNER_BINDING_SORT_KEY",
    "APPROVED_PARTITION_KEY",
    "APPROVED_SCOPE",
    "APPROVED_TABLE_NAME",
    "CurrentUserSessionStale",
    "CurrentUserStateUnavailable",
    "assert_session_current",
    "disable_current_user_state",
    "enable_current_user_state",
    "load_current_user_state",
    "load_single_owner_binding",
    "provision_current_user_state",
    "provision_single_owner_state",
    "repair_current_user_session_version",
]
