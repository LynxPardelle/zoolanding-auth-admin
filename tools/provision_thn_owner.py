#!/usr/bin/env python3
"""Operate the single TEST owner account for The Hair Narrative.

This is an operator-only CLI.  It discovers one exact dedicated Cognito pool,
client, and group, assigns the code-owned ``client-owner`` purpose, and never
calls the shared Cognito user-lifecycle service.  Provider identifiers, the
owner email, and temporary credentials are never returned or logged.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from auth_admin_current_user_v2 import (
    APPROVED_SCOPE,
    disable_current_user_state,
    enable_current_user_state,
    load_current_user_state,
    load_single_owner_binding,
    marshal_item,
    provision_single_owner_state,
    repair_current_user_session_version,
)


APPROVED_POOL_NAME = "zoolanding-auth-admin-test-ThnAuthAdminV2"
APPROVED_CLIENT_NAME = "zoolanding-auth-admin-test-ThnAuthAdminV2Client"
APPROVED_GROUP_NAME = "journal-owner"
APPROVED_STACK_NAME = "zoolanding-auth-admin-test"
APPROVED_ACCOUNT_PURPOSE = "client-owner"
APPROVED_AUDIT_TABLE_NAME = "zoolanding-auth-admin-test-ThnAuditV2"
APPROVED_AUDIT_PARTITION_KEY = "AUDIT#test#thn-journal-test-v2"
APPROVED_AWS_PARTITION = "aws"
APPROVED_AWS_REGION = "us-east-1"
APPROVED_MEDIATOR_FUNCTION = "zoolanding-auth-admin-test-ThnOwnerOperatorV2"
APPROVED_MEDIATOR_QUALIFIER = "test"
APPROVED_MEDIATOR_ALIAS = (
    f"{APPROVED_MEDIATOR_FUNCTION}:{APPROVED_MEDIATOR_QUALIFIER}"
)
# Activation must replace this inert value with the reviewed account-id digest.
# Keeping the raw account identifier out of the repository preserves the
# code-owned trust boundary without accepting a caller or environment selector.
APPROVED_AWS_ACCOUNT_ID_SHA256 = "0" * 64

_ROLE_ARN_RE = re.compile(
    r"^arn:(aws):iam::([0-9]{12}):role/"
    r"(zoolanding-thn-registry-test-operator)$"
)
_ASSUMED_ROLE_ARN_RE = re.compile(
    r"^arn:(aws):sts::([0-9]{12}):assumed-role/"
    r"(zoolanding-thn-registry-test-operator)/[^/]{1,128}$"
)
_EMAIL_RE = re.compile(r"^[^\s@]{1,128}@[^\s@]{1,190}$")
_FUNCTION_URL_RE = re.compile(
    r"^https://[a-z0-9-]+\.lambda-url\.us-east-1\.on\.aws/$"
)
_SAFE_OPERATIONS = frozenset(
    {"create", "enable", "disable", "reset", "repair-session-version"}
)


class OperatorAuthorizationError(PermissionError):
    """The active AWS principal is not the named TEST operator."""


class OperatorInputError(ValueError):
    """An owner operation input is invalid."""


class OwnerProvisioningError(RuntimeError):
    """The dedicated THN resources cannot be resolved safely."""


class OwnerOperationError(RuntimeError):
    """An owner operation failed without exposing provider details."""


def _account_is_code_owned(account_id: Any) -> bool:
    digest = APPROVED_AWS_ACCOUNT_ID_SHA256
    return (
        isinstance(account_id, str)
        and bool(re.fullmatch(r"[0-9]{12}", account_id))
        and isinstance(digest, str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", digest))
        and digest != "0" * 64
        and hmac.compare_digest(
            hashlib.sha256(account_id.encode("ascii")).hexdigest(),
            digest,
        )
    )


def require_named_operator(caller_arn: str) -> str:
    """Return the canonical role ARN for the one accepted direct/session ARN."""

    caller = str(caller_arn or "")
    for pattern in (_ROLE_ARN_RE, _ASSUMED_ROLE_ARN_RE):
        match = pattern.fullmatch(caller)
        if not match:
            continue
        partition, account_id, role_name = match.groups()
        if _account_is_code_owned(account_id):
            return f"arn:{partition}:iam::{account_id}:role/{role_name}"
    raise OperatorAuthorizationError("active AWS principal is not the named TEST operator")


def _pages(
    method: Callable[..., Mapping[str, Any]],
    result_key: str,
    **initial: Any,
) -> list[Mapping[str, Any]]:
    items: list[Mapping[str, Any]] = []
    arguments = dict(initial)
    seen_tokens: set[str] = set()
    while True:
        response = method(**arguments)
        if not isinstance(response, Mapping):
            raise OwnerProvisioningError("dedicated THN resources are unavailable")
        page = response.get(result_key)
        if not isinstance(page, list) or any(not isinstance(item, Mapping) for item in page):
            raise OwnerProvisioningError("dedicated THN resources are unavailable")
        items.extend(page)
        token = response.get("NextToken")
        if token is None:
            return items
        if not isinstance(token, str) or not token or token in seen_tokens:
            raise OwnerProvisioningError("dedicated THN resources are unavailable")
        seen_tokens.add(token)
        arguments["NextToken"] = token


def _one_exact(
    items: Sequence[Mapping[str, Any]],
    *,
    field: str,
    value: str,
) -> Mapping[str, Any]:
    matches = [item for item in items if item.get(field) == value]
    if len(matches) != 1:
        raise OwnerProvisioningError("dedicated THN resources are unavailable")
    candidate = matches[0]
    if any("zoosite" in str(part).lower() for part in candidate.values()):
        raise OwnerProvisioningError("dedicated THN resources are unavailable")
    return candidate


def _stack_physical_id(cloudformation_client: Any, logical_id: str) -> str:
    response = cloudformation_client.describe_stack_resource(
        StackName=APPROVED_STACK_NAME,
        LogicalResourceId=logical_id,
    )
    if not isinstance(response, Mapping):
        raise OwnerProvisioningError("dedicated THN resources are unavailable")
    detail = response.get("StackResourceDetail")
    if not isinstance(detail, Mapping):
        raise OwnerProvisioningError("dedicated THN resources are unavailable")
    physical_id = detail.get("PhysicalResourceId")
    status = detail.get("ResourceStatus")
    if (
        detail.get("LogicalResourceId") != logical_id
        or not isinstance(physical_id, str)
        or not physical_id
        or "zoosite" in physical_id.lower()
        or not isinstance(status, str)
        or status.endswith("FAILED")
        or status.startswith("DELETE")
    ):
        raise OwnerProvisioningError("dedicated THN resources are unavailable")
    return physical_id


def discover_dedicated_resources(
    cognito_client: Any,
    cloudformation_client: Any,
) -> dict[str, str]:
    """Resolve one exact secure TEST pool/client/group or fail closed."""

    try:
        stack_pool_id = _stack_physical_id(
            cloudformation_client,
            "ThnAuthAdminV2UserPool",
        )
        stack_client_id = _stack_physical_id(
            cloudformation_client,
            "ThnAuthAdminV2UserPoolClient",
        )
        stack_group_name = _stack_physical_id(
            cloudformation_client,
            "ThnAuthAdminV2OwnerGroup",
        )
        pool_id = stack_pool_id
        if (
            not isinstance(pool_id, str)
            or "zoosite" in pool_id.lower()
            or stack_group_name != APPROVED_GROUP_NAME
        ):
            raise OwnerProvisioningError("dedicated THN resources are unavailable")
        described_pool_response = cognito_client.describe_user_pool(UserPoolId=pool_id)
        if not isinstance(described_pool_response, Mapping):
            raise OwnerProvisioningError("dedicated THN resources are unavailable")
        pool = described_pool_response.get("UserPool")
        if not isinstance(pool, Mapping):
            raise OwnerProvisioningError("dedicated THN resources are unavailable")
        if (
            pool.get("Id") != pool_id
            or pool.get("Name") != APPROVED_POOL_NAME
            or (pool.get("AdminCreateUserConfig") or {}).get("AllowAdminCreateUserOnly")
            is not True
            or pool.get("MfaConfiguration") != "ON"
            or set(pool.get("EnabledMfas") or []) != {"SOFTWARE_TOKEN_MFA"}
            or bool(pool.get("LambdaConfig"))
            or (pool.get("AccountRecoverySetting") or {}).get("RecoveryMechanisms")
            != [{"Priority": 1, "Name": "admin_only"}]
        ):
            raise OwnerProvisioningError("dedicated THN resources are unavailable")

        client_id = stack_client_id
        if (
            not isinstance(client_id, str)
            or "zoosite" in client_id.lower()
        ):
            raise OwnerProvisioningError("dedicated THN resources are unavailable")
        described_client_response = cognito_client.describe_user_pool_client(
            UserPoolId=pool_id,
            ClientId=client_id,
        )
        if not isinstance(described_client_response, Mapping):
            raise OwnerProvisioningError("dedicated THN resources are unavailable")
        client = described_client_response.get("UserPoolClient")
        if not isinstance(client, Mapping):
            raise OwnerProvisioningError("dedicated THN resources are unavailable")
        if (
            client.get("UserPoolId") != pool_id
            or client.get("ClientId") != client_id
            or client.get("ClientName") != APPROVED_CLIENT_NAME
            or set(client.get("ExplicitAuthFlows") or [])
            != {"ALLOW_ADMIN_USER_PASSWORD_AUTH"}
            or client.get("PreventUserExistenceErrors") != "ENABLED"
            or client.get("EnableTokenRevocation") is not True
            or type(client.get("AuthSessionValidity")) is not int
            or client.get("AuthSessionValidity") != 5
            or bool(client.get("ClientSecret"))
        ):
            raise OwnerProvisioningError("dedicated THN resources are unavailable")

        group_response = cognito_client.get_group(
            UserPoolId=pool_id,
            GroupName=APPROVED_GROUP_NAME,
        )
        group = group_response.get("Group") if isinstance(group_response, Mapping) else None
        if (
            not isinstance(group, Mapping)
            or group.get("GroupName") != APPROVED_GROUP_NAME
            or group.get("RoleArn")
            or group.get("Precedence") is not None
        ):
            raise OwnerProvisioningError("dedicated THN resources are unavailable")
        return {
            "userPoolId": pool_id,
            "clientId": client_id,
            "groupName": APPROVED_GROUP_NAME,
        }
    except OwnerProvisioningError:
        raise
    except Exception:
        raise OwnerProvisioningError("dedicated THN resources are unavailable") from None


def _validate_username(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 320 or not _EMAIL_RE.fullmatch(value):
        raise OperatorInputError("owner input is invalid")
    return value


def _validate_temporary_password(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 14 <= len(value) <= 256
        or any(character.isspace() for character in value)
        or not re.search(r"[a-z]", value)
        or not re.search(r"[A-Z]", value)
        or not re.search(r"[0-9]", value)
        or not re.search(r"[^A-Za-z0-9]", value)
    ):
        raise OperatorInputError("owner input is invalid")
    return value


def _user_identity(
    response: Any,
    *,
    created: bool,
    expected_email: str,
) -> tuple[str, str]:
    if not isinstance(response, Mapping):
        raise OwnerOperationError("owner operation failed")
    user = response.get("User") if created else response
    if not isinstance(user, Mapping):
        raise OwnerOperationError("owner operation failed")
    username = user.get("Username")
    attributes = user.get("Attributes") if created else user.get("UserAttributes")
    if not isinstance(username, str) or not username or not isinstance(attributes, list):
        raise OwnerOperationError("owner operation failed")
    attribute_map: dict[str, list[Any]] = {}
    for item in attributes:
        if not isinstance(item, Mapping):
            raise OwnerOperationError("owner operation failed")
        name = item.get("Name")
        if not isinstance(name, str):
            raise OwnerOperationError("owner operation failed")
        attribute_map.setdefault(name, []).append(item.get("Value"))
    subjects = attribute_map.get("sub", [])
    if len(subjects) != 1 or not isinstance(subjects[0], str) or not subjects[0]:
        raise OwnerOperationError("owner operation failed")
    if (
        attribute_map.get("email") != [expected_email]
        or attribute_map.get("email_verified") != ["true"]
        or (
            user.get("UserStatus") != "FORCE_CHANGE_PASSWORD"
            if created
            else user.get("UserStatus")
            not in {"FORCE_CHANGE_PASSWORD", "CONFIRMED", "RESET_REQUIRED"}
        )
    ):
        raise OwnerOperationError("owner operation failed")
    return username, subjects[0]


def _safe_result(operation: str, state: Any) -> dict[str, Any]:
    if not isinstance(state, Mapping):
        raise OwnerOperationError("owner operation failed")
    purpose = state.get("accountPurpose")
    version = state.get("sessionVersion")
    enabled = state.get("enabled")
    if (
        purpose != APPROVED_ACCOUNT_PURPOSE
        or isinstance(version, bool)
        or not isinstance(version, int)
        or version < 1
        or type(enabled) is not bool
    ):
        raise OwnerOperationError("owner operation failed")
    return {
        "ok": True,
        "operation": operation,
        "accountPurpose": APPROVED_ACCOUNT_PURPOSE,
        "sessionVersion": version,
        "enabled": enabled,
    }


def _owner_group_users(cognito_client: Any, *, pool_id: str) -> list[Mapping[str, Any]]:
    try:
        return _pages(
            cognito_client.list_users_in_group,
            "Users",
            UserPoolId=pool_id,
            GroupName=APPROVED_GROUP_NAME,
            Limit=60,
        )
    except Exception:
        raise OwnerOperationError("owner operation failed") from None


def _user_subject(user: Mapping[str, Any]) -> tuple[str, str]:
    username = user.get("Username")
    attributes = user.get("Attributes")
    if not isinstance(username, str) or not username or not isinstance(attributes, list):
        raise OwnerOperationError("owner operation failed")
    subjects = [
        item.get("Value")
        for item in attributes
        if isinstance(item, Mapping) and item.get("Name") == "sub"
    ]
    if len(subjects) != 1 or not isinstance(subjects[0], str) or not subjects[0]:
        raise OwnerOperationError("owner operation failed")
    return username, subjects[0]


def _require_group_available(
    cognito_client: Any,
    *,
    pool_id: str,
    username: str,
    subject: str,
    created: bool,
) -> bool:
    users = _owner_group_users(cognito_client, pool_id=pool_id)
    if created:
        if users:
            raise OwnerOperationError("owner operation failed")
        return False
    if not users:
        return False
    if len(users) != 1 or _user_subject(users[0]) != (username, subject):
        raise OwnerOperationError("owner operation failed")
    return True


def _require_exact_user_group(
    cognito_client: Any,
    *,
    pool_id: str,
    username: str,
    subject: str,
) -> None:
    try:
        groups = _pages(
            cognito_client.admin_list_groups_for_user,
            "Groups",
            UserPoolId=pool_id,
            Username=username,
            Limit=60,
        )
    except Exception:
        raise OwnerOperationError("owner operation failed") from None
    names = [group.get("GroupName") for group in groups]
    if names != [APPROVED_GROUP_NAME]:
        raise OwnerOperationError("owner operation failed")
    users = _owner_group_users(cognito_client, pool_id=pool_id)
    if len(users) != 1 or _user_subject(users[0]) != (username, subject):
        raise OwnerOperationError("owner operation failed")


def _provider_error_code(error: BaseException) -> str:
    response = getattr(error, "response", None)
    if not isinstance(response, Mapping):
        return ""
    detail = response.get("Error")
    if not isinstance(detail, Mapping):
        return ""
    code = detail.get("Code")
    return code if isinstance(code, str) else ""


def _audit_event(
    *,
    operation: str,
    phase: str,
    operation_id: str,
    state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if operation not in _SAFE_OPERATIONS or phase not in {"intent", "completed", "failed"}:
        raise OwnerOperationError("owner audit event is invalid")
    if not re.fullmatch(r"[0-9a-f]{32}", operation_id):
        raise OwnerOperationError("owner audit event is invalid")
    event: dict[str, Any] = {
        "operation": operation,
        "phase": phase,
        "operationId": operation_id,
        "accountPurpose": APPROVED_ACCOUNT_PURPOSE,
    }
    if phase == "completed":
        safe = _safe_result(operation, state)
        event.update(
            {
                "sessionVersion": safe["sessionVersion"],
                "enabled": safe["enabled"],
            }
        )
    elif state is not None:
        raise OwnerOperationError("owner audit event is invalid")
    return event


def execute_operation(
    session: Any,
    *,
    state_client: Any,
    operation: str,
    username: str,
    temporary_password: str | None = None,
    event_sink: Callable[[Mapping[str, Any]], Any] | None = None,
    authorized_by_mediator: bool = False,
) -> dict[str, Any]:
    """Execute one closed owner transition after exact operator verification."""

    if getattr(session, "region_name", None) != APPROVED_AWS_REGION:
        raise OperatorAuthorizationError("active AWS region is not the named TEST region")
    if type(authorized_by_mediator) is not bool:
        raise OperatorAuthorizationError("owner execution boundary is invalid")
    if not authorized_by_mediator:
        identity = session.client("sts").get_caller_identity()
        if not isinstance(identity, Mapping):
            raise OperatorAuthorizationError("active AWS principal identity is invalid")
        if not _account_is_code_owned(identity.get("Account")):
            raise OperatorAuthorizationError("active AWS principal is not the named TEST operator")
        require_named_operator(str(identity.get("Arn") or ""))

    if operation not in _SAFE_OPERATIONS:
        raise OperatorInputError("owner input is invalid")
    trusted_username = _validate_username(username)
    trusted_password: str | None = None
    if operation in {"create", "reset"}:
        trusted_password = _validate_temporary_password(temporary_password)
    elif temporary_password is not None:
        raise OperatorInputError("owner input is invalid")

    try:
        cloudformation = session.client("cloudformation")
        cognito = session.client("cognito-idp")
        resources = discover_dedicated_resources(cognito, cloudformation)
        pool_id = resources["userPoolId"]
        if event_sink is None:
            raise OwnerOperationError("owner audit sink is required")
        operation_id = uuid.uuid4().hex
        event_sink(
            _audit_event(
                operation=operation,
                phase="intent",
                operation_id=operation_id,
            )
        )

        try:
            if operation == "create":
                created_new = False
                identity_uses_created_shape = False
                group_added = False
                provider_username = trusted_username
                try:
                    try:
                        provider_response = cognito.admin_get_user(
                            UserPoolId=pool_id, Username=trusted_username
                        )
                    except Exception as error:
                        if _provider_error_code(error) != "UserNotFoundException":
                            raise
                        try:
                            provider_response = cognito.admin_create_user(
                                UserPoolId=pool_id,
                                Username=trusted_username,
                                TemporaryPassword=trusted_password,
                                MessageAction="SUPPRESS",
                                UserAttributes=[
                                    {"Name": "email", "Value": trusted_username},
                                    {"Name": "email_verified", "Value": "true"},
                                ],
                            )
                            created_new = True
                            identity_uses_created_shape = True
                        except Exception as create_error:
                            try:
                                provider_response = cognito.admin_get_user(
                                    UserPoolId=pool_id,
                                    Username=trusted_username,
                                )
                            except Exception:
                                raise create_error
                            # A read after an ambiguous create failure cannot
                            # prove which concurrent execution created the user.
                            # Abort this run before state or group mutation. A
                            # later run can safely reconcile the account after
                            # observing it as pre-existing during its preflight.
                            raise OwnerOperationError(
                                "owner create outcome is ambiguous; retry create"
                            ) from None
                    provider_username, subject = _user_identity(
                        provider_response,
                        created=identity_uses_created_shape,
                        expected_email=trusted_username,
                    )
                    already_in_group = _require_group_available(
                        cognito,
                        pool_id=pool_id,
                        username=provider_username,
                        subject=subject,
                        created=created_new,
                    )
                    state = state_client.provision(
                        subject=subject,
                        account_purpose=APPROVED_ACCOUNT_PURPOSE,
                    )
                    if not already_in_group:
                        cognito.admin_add_user_to_group(
                            UserPoolId=pool_id,
                            Username=provider_username,
                            GroupName=APPROVED_GROUP_NAME,
                        )
                        group_added = True
                    _require_exact_user_group(
                        cognito,
                        pool_id=pool_id,
                        username=provider_username,
                        subject=subject,
                    )
                except Exception:
                    if group_added:
                        try:
                            cognito.admin_remove_user_from_group(
                                UserPoolId=pool_id,
                                Username=provider_username,
                                GroupName=APPROVED_GROUP_NAME,
                            )
                        except Exception:
                            pass
                    if created_new:
                        try:
                            cognito.admin_disable_user(
                                UserPoolId=pool_id,
                                Username=provider_username,
                            )
                        except Exception:
                            pass
                    raise
            else:
                provider_username, subject = _user_identity(
                    cognito.admin_get_user(UserPoolId=pool_id, Username=trusted_username),
                    created=False,
                    expected_email=trusted_username,
                )
                if operation in {"enable", "repair-session-version"}:
                    _require_exact_user_group(
                        cognito,
                        pool_id=pool_id,
                        username=provider_username,
                        subject=subject,
                    )
                if operation == "enable":
                    state = state_client.enable(
                        subject=subject,
                        account_purpose=APPROVED_ACCOUNT_PURPOSE,
                    )
                    cognito.admin_enable_user(
                        UserPoolId=pool_id,
                        Username=provider_username,
                    )
                elif operation == "disable":
                    state = state_client.disable(
                        subject=subject,
                        account_purpose=APPROVED_ACCOUNT_PURPOSE,
                    )
                    cognito.admin_user_global_sign_out(
                        UserPoolId=pool_id,
                        Username=provider_username,
                    )
                    cognito.admin_disable_user(
                        UserPoolId=pool_id,
                        Username=provider_username,
                    )
                elif operation == "reset":
                    state = state_client.reset(
                        subject=subject,
                        account_purpose=APPROVED_ACCOUNT_PURPOSE,
                    )
                    cognito.admin_disable_user(
                        UserPoolId=pool_id,
                        Username=provider_username,
                    )
                    cognito.admin_user_global_sign_out(
                        UserPoolId=pool_id,
                        Username=provider_username,
                    )
                    cognito.admin_set_user_password(
                        UserPoolId=pool_id,
                        Username=provider_username,
                        Password=trusted_password,
                        Permanent=False,
                    )
                    try:
                        cognito.admin_delete_software_token(
                            UserPoolId=pool_id,
                            Username=provider_username,
                        )
                    except Exception as error:
                        if _provider_error_code(error) != "ResourceNotFoundException":
                            raise
                else:
                    state = state_client.repair_session_version(
                        subject=subject,
                        account_purpose=APPROVED_ACCOUNT_PURPOSE,
                    )
        except Exception:
            try:
                event_sink(
                    _audit_event(
                        operation=operation,
                        phase="failed",
                        operation_id=operation_id,
                    )
                )
            except Exception:
                pass
            raise

        result = _safe_result(operation, state)
        event_sink(
            _audit_event(
                operation=operation,
                phase="completed",
                operation_id=operation_id,
                state=result,
            )
        )
        return result
    except (OperatorAuthorizationError, OperatorInputError, OwnerProvisioningError, OwnerOperationError):
        raise
    except Exception:
        raise OwnerOperationError("owner operation failed") from None


class DynamoCurrentUserStateClient:
    """Narrow adapter over the exact THN current-user-state contract."""

    def __init__(self, dynamodb_client: Any):
        self._dynamodb = dynamodb_client

    def _load(self, subject: str) -> dict[str, Any]:
        binding = load_single_owner_binding(
            self._dynamodb,
            scope=APPROVED_SCOPE,
        )
        state = load_current_user_state(
            self._dynamodb,
            scope=APPROVED_SCOPE,
            subject=subject,
        )
        if (
            binding.get("subject") != subject
            or binding.get("accountPurpose") != APPROVED_ACCOUNT_PURPOSE
            or state.get("accountPurpose") != APPROVED_ACCOUNT_PURPOSE
        ):
            raise OwnerOperationError("owner operation failed")
        return state

    def provision(self, *, subject: str, account_purpose: str) -> dict[str, Any]:
        return provision_single_owner_state(
            self._dynamodb,
            scope=APPROVED_SCOPE,
            subject=subject,
            account_purpose=account_purpose,
        )

    def enable(self, *, subject: str, account_purpose: str) -> dict[str, Any]:
        current = self._load(subject)
        if current["enabled"] is True:
            return current
        return enable_current_user_state(
            self._dynamodb,
            scope=APPROVED_SCOPE,
            subject=subject,
            account_purpose=account_purpose,
            session_version=int(current["sessionVersion"]),
        )

    def disable(self, *, subject: str, account_purpose: str) -> dict[str, Any]:
        current = self._load(subject)
        if current["enabled"] is False:
            return current
        return disable_current_user_state(
            self._dynamodb,
            scope=APPROVED_SCOPE,
            subject=subject,
            account_purpose=account_purpose,
            session_version=int(current["sessionVersion"]),
        )

    def reset(self, *, subject: str, account_purpose: str) -> dict[str, Any]:
        current = self._load(subject)
        if current["enabled"] is True:
            return disable_current_user_state(
                self._dynamodb,
                scope=APPROVED_SCOPE,
                subject=subject,
                account_purpose=account_purpose,
                session_version=int(current["sessionVersion"]),
            )
        return repair_current_user_session_version(
            self._dynamodb,
            scope=APPROVED_SCOPE,
            subject=subject,
            account_purpose=account_purpose,
            session_version=int(current["sessionVersion"]),
            enabled=False,
        )

    def repair_session_version(
        self,
        *,
        subject: str,
        account_purpose: str,
    ) -> dict[str, Any]:
        current = self._load(subject)
        return repair_current_user_session_version(
            self._dynamodb,
            scope=APPROVED_SCOPE,
            subject=subject,
            account_purpose=account_purpose,
            session_version=int(current["sessionVersion"]),
            enabled=bool(current["enabled"]),
        )


class DynamoAuditEventSink:
    """Write one sanitized create-only event in the reviewed operator path."""

    def __init__(self, dynamodb_client: Any):
        self._dynamodb = dynamodb_client

    def __call__(self, event: Mapping[str, Any]) -> None:
        operation = event.get("operation")
        phase = event.get("phase")
        operation_id = event.get("operationId")
        purpose = event.get("accountPurpose")
        expected_fields = {"operation", "phase", "operationId", "accountPurpose"}
        if phase == "completed":
            expected_fields |= {"sessionVersion", "enabled"}
        if (
            not isinstance(event, Mapping)
            or set(event) != expected_fields
            or operation not in _SAFE_OPERATIONS
            or phase not in {"intent", "completed", "failed"}
            or not isinstance(operation_id, str)
            or not re.fullmatch(r"[0-9a-f]{32}", operation_id)
            or purpose != APPROVED_ACCOUNT_PURPOSE
        ):
            raise OwnerOperationError("owner audit event is invalid")
        safe: dict[str, Any] | None = None
        if phase == "completed":
            safe = _safe_result(str(operation), event)
        now_ms = int(time.time() * 1000)
        event_id = uuid.uuid4().hex
        item = {
            "pk": APPROVED_AUDIT_PARTITION_KEY,
            "sk": f"EVENT#{now_ms:013d}#{event_id}",
            "contractVersion": 1,
            "operation": operation,
            "phase": phase,
            "operationId": operation_id,
            "accountPurpose": APPROVED_ACCOUNT_PURPOSE,
            "occurredAtEpochMs": now_ms,
        }
        if safe is not None:
            item["sessionVersion"] = safe["sessionVersion"]
            item["enabled"] = safe["enabled"]
        try:
            self._dynamodb.put_item(
                TableName=APPROVED_AUDIT_TABLE_NAME,
                Item=marshal_item(item),
                ConditionExpression="attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
                ExpressionAttributeNames={"#pk": "pk", "#sk": "sk"},
                ReturnValues="NONE",
                ReturnValuesOnConditionCheckFailure="NONE",
            )
        except Exception:
            raise OwnerOperationError("owner audit append failed") from None


class SanitizedArgumentParser(argparse.ArgumentParser):
    """Reject invalid CLI input without reflecting raw arguments to stderr."""

    def error(self, message: str) -> None:
        del message
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


def build_parser() -> argparse.ArgumentParser:
    parser = SanitizedArgumentParser(
        description="Operate the dedicated THN TEST owner account."
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("create", "enable", "disable", "reset", "repair-session-version"):
        subparsers.add_parser(operation)
    return parser


def _signed_function_url_post(
    session: Any,
    function_url: str,
    payload: bytes,
) -> tuple[int, dict[str, str], bytes]:
    """POST one SigV4-signed request without redirects or response logging."""

    if (
        not isinstance(function_url, str)
        or not _FUNCTION_URL_RE.fullmatch(function_url)
        or not isinstance(payload, bytes)
        or not payload
        or len(payload) > 4096
    ):
        raise OwnerOperationError("owner operation failed")
    try:
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.httpsession import URLLib3Session

        credentials = session.get_credentials()
        frozen = credentials.get_frozen_credentials() if credentials is not None else None
        if frozen is None:
            raise OwnerOperationError("owner operation failed")
        request = AWSRequest(
            method="POST",
            url=function_url,
            data=payload,
            headers={"content-type": "application/json"},
        )
        SigV4Auth(frozen, "lambda", APPROVED_AWS_REGION).add_auth(request)
        response = URLLib3Session(timeout=65).send(request.prepare())
        status_code = int(response.status_code)
        headers = {
            str(key).lower(): str(value)
            for key, value in dict(response.headers or {}).items()
        }
        raw = response.content
        if not isinstance(raw, bytes):
            raise OwnerOperationError("owner operation failed")
        return status_code, headers, raw
    except OwnerOperationError:
        raise
    except Exception:
        raise OwnerOperationError("owner operation failed") from None


def invoke_owner_operator(
    session: Any,
    *,
    operation: str,
    username: str,
    temporary_password: str | None = None,
) -> dict[str, Any]:
    """Invoke only the reviewed synchronous mediator alias and sanitize its reply."""

    if getattr(session, "region_name", None) != APPROVED_AWS_REGION:
        raise OperatorAuthorizationError("active AWS region is not the named TEST region")
    identity = session.client("sts").get_caller_identity()
    if not isinstance(identity, Mapping):
        raise OperatorAuthorizationError("active AWS principal identity is invalid")
    if not _account_is_code_owned(identity.get("Account")):
        raise OperatorAuthorizationError("active AWS principal is not the named TEST operator")
    require_named_operator(str(identity.get("Arn") or ""))

    if operation not in _SAFE_OPERATIONS:
        raise OperatorInputError("owner input is invalid")
    trusted_username = _validate_username(username)
    request: dict[str, Any] = {
        "contractVersion": 1,
        "operation": operation,
        "username": trusted_username,
    }
    if operation in {"create", "reset"}:
        request["temporaryPassword"] = _validate_temporary_password(
            temporary_password
        )
    elif temporary_password is not None:
        raise OperatorInputError("owner input is invalid")

    try:
        lambda_client = session.client("lambda")
        function_url_response = lambda_client.get_function_url_config(
            FunctionName=APPROVED_MEDIATOR_FUNCTION,
            Qualifier=APPROVED_MEDIATOR_QUALIFIER,
        )
        function_url = (
            function_url_response.get("FunctionUrl")
            if isinstance(function_url_response, Mapping)
            else None
        )
        if (
            not isinstance(function_url, str)
            or not _FUNCTION_URL_RE.fullmatch(function_url)
            or function_url_response.get("AuthType") != "AWS_IAM"
        ):
            raise OwnerOperationError("owner operation failed")
        payload = json.dumps(
            request,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        status_code, headers, raw = _signed_function_url_post(
            session,
            function_url,
            payload,
        )
        if (
            status_code != 200
            or not headers.get("content-type", "").lower().startswith(
                "application/json"
            )
            or "no-store" not in headers.get("cache-control", "").lower()
        ):
            raise OwnerOperationError("owner operation failed")
        if not isinstance(raw, bytes) or len(raw) > 4096:
            raise OwnerOperationError("owner operation failed")
        result = json.loads(raw.decode("utf-8"))
        if not isinstance(result, Mapping):
            raise OwnerOperationError("owner operation failed")
        if result.get("ok") is not True:
            raise OwnerOperationError("owner operation failed")
        if set(result) != {
            "ok",
            "operation",
            "accountPurpose",
            "sessionVersion",
            "enabled",
        } or result.get("operation") != operation:
            raise OwnerOperationError("owner operation failed")
        return _safe_result(operation, result)
    except (
        OperatorAuthorizationError,
        OperatorInputError,
        OwnerProvisioningError,
        OwnerOperationError,
    ):
        raise
    except Exception:
        raise OwnerOperationError("owner operation failed") from None


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        username = input("Owner email: ").strip()
        password = None
        if args.operation in {"create", "reset"}:
            password = getpass.getpass("Temporary password: ")
        import boto3

        session = boto3.Session(region_name=APPROVED_AWS_REGION)
        result = invoke_owner_operator(
            session,
            operation=args.operation,
            username=username,
            temporary_password=password,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (
        OperatorAuthorizationError,
        OperatorInputError,
        OwnerProvisioningError,
        OwnerOperationError,
    ) as error:
        print(json.dumps({"ok": False, "error": str(error)}, separators=(",", ":")), file=sys.stderr)
        return 2
    except Exception:
        print(json.dumps({"ok": False, "error": "owner operation failed"}, separators=(",", ":")), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
