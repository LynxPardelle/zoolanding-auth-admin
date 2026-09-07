"""Signed function-URL mediator for the single THN TEST owner lifecycle."""

from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any

from tools import provision_thn_owner as owner


DynamoAuditEventSink = owner.DynamoAuditEventSink
DynamoCurrentUserStateClient = owner.DynamoCurrentUserStateClient
execute_operation = owner.execute_operation

_OPERATIONS = frozenset(
    {"create", "enable", "disable", "reset", "repair-session-version"}
)
_FAILURE = {"ok": False, "error": "owner operation failed"}
_MAX_REQUEST_BYTES = 4096
_RESPONSE_HEADERS = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store, max-age=0",
    "pragma": "no-cache",
    "expires": "0",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
}


class OwnerMediatorFailure(RuntimeError):
    """Sanitized runtime failure that increments the native Lambda error metric."""


def _new_session() -> Any:
    import boto3

    return boto3.Session(region_name=owner.APPROVED_AWS_REGION)


def _validated_request(event: Any) -> dict[str, Any]:
    if not isinstance(event, Mapping):
        raise owner.OperatorInputError("owner input is invalid")
    operation = event.get("operation")
    expected = {"contractVersion", "operation", "username"}
    if operation in {"create", "reset"}:
        expected.add("temporaryPassword")
    if (
        set(event) != expected
        or type(event.get("contractVersion")) is not int
        or event.get("contractVersion") != 1
        or operation not in _OPERATIONS
    ):
        raise owner.OperatorInputError("owner input is invalid")
    request = {
        "operation": str(operation),
        "username": owner._validate_username(event.get("username")),
        "temporary_password": None,
    }
    if operation in {"create", "reset"}:
        request["temporary_password"] = owner._validate_temporary_password(
            event.get("temporaryPassword")
        )
    return request


def _function_url_request(event: Any) -> dict[str, Any]:
    if not isinstance(event, Mapping):
        raise owner.OperatorInputError("owner input is invalid")
    request_context = event.get("requestContext")
    if not isinstance(request_context, Mapping):
        raise owner.OperatorInputError("owner input is invalid")
    http = request_context.get("http")
    headers = event.get("headers")
    body = event.get("body")
    if (
        event.get("version") != "2.0"
        or event.get("routeKey") != "$default"
        or event.get("rawPath") != "/"
        or event.get("rawQueryString") != ""
        or event.get("isBase64Encoded") is not False
        or not isinstance(http, Mapping)
        or http.get("method") != "POST"
        or http.get("path") != "/"
        or not isinstance(headers, Mapping)
        or not str(headers.get("content-type") or "").lower().startswith(
            "application/json"
        )
        or not isinstance(body, str)
        or not body
        or len(body.encode("utf-8")) > _MAX_REQUEST_BYTES
    ):
        raise owner.OperatorInputError("owner input is invalid")
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        raise owner.OperatorInputError("owner input is invalid") from None
    request = _validated_request(payload)

    authorizer = request_context.get("authorizer")
    iam = authorizer.get("iam") if isinstance(authorizer, Mapping) else None
    caller_arn = iam.get("userArn") if isinstance(iam, Mapping) else None
    owner.require_named_operator(str(caller_arn or ""))
    return request


def _http_response(status_code: int, payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": dict(_RESPONSE_HEADERS),
        "body": json.dumps(dict(payload), sort_keys=True, separators=(",", ":")),
        "isBase64Encoded": False,
    }


def _public_result(result: Any, operation: str) -> dict[str, Any]:
    if not isinstance(result, Mapping) or set(result) != {
        "ok",
        "operation",
        "accountPurpose",
        "sessionVersion",
        "enabled",
    }:
        raise owner.OwnerOperationError("owner operation failed")
    if result.get("ok") is not True or result.get("operation") != operation:
        raise owner.OwnerOperationError("owner operation failed")
    return owner._safe_result(operation, result)


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    del context
    try:
        request = _function_url_request(event)
    except owner.OperatorAuthorizationError:
        return _http_response(403, _FAILURE)
    except Exception:
        return _http_response(400, _FAILURE)
    try:
        session = _new_session()
        dynamodb = session.client("dynamodb")
        result = execute_operation(
            session,
            state_client=DynamoCurrentUserStateClient(dynamodb),
            operation=request["operation"],
            username=request["username"],
            temporary_password=request["temporary_password"],
            event_sink=DynamoAuditEventSink(dynamodb),
            authorized_by_mediator=True,
        )
        return _http_response(200, _public_result(result, request["operation"]))
    except Exception:
        raise OwnerMediatorFailure("owner operation failed") from None
