"""Dedicated TEST-only Auth Admin v2 session boundary for The Hair Narrative.

This module is intentionally additive.  The legacy ``/auth/*`` handler never
imports it.  The dedicated v2 Lambda uses this module's ``lambda_handler``
directly for only the closed ``/auth-v2/*`` route inventory.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import time
from copy import deepcopy
from typing import Any, Mapping, Optional

from auth_admin_current_user_v2 import (
    APPROVED_PARTITION_KEY,
    APPROVED_SCOPE,
    APPROVED_TABLE_NAME,
    CurrentUserSessionStale,
    CurrentUserStateUnavailable,
    assert_session_current,
)


ENVIRONMENT = "test"
DOMAIN = "thehairnarrative.com"
AUTH_PROFILE_ID = "journal-owner"
HUB_ID = "thehairnarrative-com-journal"
ADMIN_HOST = "admin-test.thehairnarrative.com"
ADMIN_ORIGIN = f"https://{ADMIN_HOST}"


def _cookie_namespace() -> str:
    seed = f"{ENVIRONMENT}|{DOMAIN}|{AUTH_PROFILE_ID}|{HUB_ID}".encode("utf-8")
    return base64.b32encode(hashlib.sha256(seed).digest()).decode("ascii").lower()[:20]


COOKIE_NAMESPACE = _cookie_namespace()
if COOKIE_NAMESPACE != "endefiz7dkk635k6di6k":  # immutable contract guard
    raise RuntimeError("Auth Admin v2 cookie namespace mismatch")

SESSION_COOKIE_NAME = f"__Host-zlp_session_{COOKIE_NAMESPACE}"
CHALLENGE_COOKIE_NAME = f"__Host-zlp_challenge_{COOKIE_NAMESPACE}"
MFA_ENROLLMENT_COOKIE_NAME = f"__Host-zlp_mfa_enroll_{COOKIE_NAMESPACE}"
CSRF_COOKIE_NAME = f"zlp_csrf_{COOKIE_NAMESPACE}"
CHALLENGE_CSRF_COOKIE_NAME = f"zlp_challenge_csrf_{COOKIE_NAMESPACE}"
MFA_ENROLLMENT_CSRF_COOKIE_NAME = f"zlp_mfa_enroll_csrf_{COOKIE_NAMESPACE}"
CSRF_HEADER_NAME = "x-zlp-csrf"

SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 12 * 60 * 60
STATE_SECONDS = 5 * 60
FAILURE_WINDOW_SECONDS = 15 * 60
SIGNIN_ACCOUNT_FAILURE_LIMIT = 5
SIGNIN_IP_FAILURE_LIMIT = 10
CHALLENGE_ACCOUNT_FAILURE_LIMIT = 5
CHALLENGE_IP_FAILURE_LIMIT = 5

SESSION_TABLE_NAME = "zoolanding-auth-admin-test-ThnSessionV2"
CHALLENGE_TABLE_NAME = "zoolanding-auth-admin-test-ThnChallengeV2"
THROTTLE_TABLE_NAME = "zoolanding-auth-admin-test-ThnThrottleV2"

_SCOPE = deepcopy(dict(APPROVED_SCOPE))
_ALLOWED_CHALLENGES = frozenset(
    {"NEW_PASSWORD_REQUIRED", "SOFTWARE_TOKEN_MFA", "MFA_SETUP"}
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_TOTP_RE = re.compile(r"^[0-9]{6}$")


class AuthV2Error(RuntimeError):
    status_code = 400
    public_error = "Invalid request"
    error_code = "invalid_request"


class AuthV2AuthFailed(AuthV2Error):
    status_code = 401
    public_error = "Authentication failed"
    error_code = "auth_failed"


class AuthV2SessionRequired(AuthV2Error):
    status_code = 401
    public_error = "Authentication required"
    error_code = "auth_required"


class AuthV2Throttled(AuthV2Error):
    status_code = 429
    public_error = "Authentication temporarily unavailable"
    error_code = "auth_throttled"


class AuthV2OriginDenied(AuthV2Error):
    status_code = 403
    public_error = "Request origin denied"
    error_code = "auth_origin_denied"


class AuthV2CsrfDenied(AuthV2Error):
    status_code = 403
    public_error = "Request verification failed"
    error_code = "csrf_denied"


class AuthV2NotFound(AuthV2Error):
    status_code = 404
    public_error = "Not found"
    error_code = "not_found"


class AuthV2Unavailable(AuthV2Error):
    status_code = 503
    public_error = "Authentication temporarily unavailable"
    error_code = "auth_unavailable"


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    try:
        _require_admin_origin(event)
        _require_active_service_binding()
        method = _method(event)
        path = _path(event)
        if path == "/auth-v2/session/signin" and method == "POST":
            return _signin_response(event)
        if path == "/auth-v2/session/challenge/respond" and method == "POST":
            return _challenge_response(event)
        if path == "/auth-v2/session/mfa/setup" and method == "POST":
            return _mfa_setup_response(event)
        if path == "/auth-v2/session/mfa/verify" and method == "POST":
            return _mfa_verify_response(event)
        if path == "/auth-v2/session/me" and method == "GET":
            session = _require_session(event, touch=True)
            return _json_response(200, _public_session_payload(session))
        if path == "/auth-v2/session/logout" and method == "POST":
            return _logout_response(event)
        raise AuthV2NotFound()
    except AuthV2Error as exc:
        return _json_response(
            exc.status_code,
            {"ok": False, "error": exc.public_error, "errorCode": exc.error_code},
        )
    except (ValueError, TypeError, json.JSONDecodeError):
        return _json_response(
            400,
            {"ok": False, "error": "Invalid request", "errorCode": "invalid_request"},
        )
    except Exception:
        _safe_log("ERROR", "Auth Admin v2 request failed", code="internal_error")
        return _json_response(
            500,
            {"ok": False, "error": "Internal error", "errorCode": "internal_error"},
        )

def _signin_response(event: dict[str, Any]) -> dict[str, Any]:
    payload = _payload(event, auth_failure=True)
    try:
        email = _email(payload.get("email"))
        password = _password(payload.get("password"))
        source_ip = _source_ip(event)
    except (ValueError, TypeError) as exc:
        raise AuthV2AuthFailed() from exc

    _cognito_configuration()
    store = _session_store()
    account_hash = _sha256(email)
    ip_hash = _sha256(source_ip)
    reservation = _begin_failure_attempt(
        store,
        operation="signin",
        account_hash=account_hash,
        ip_hash=ip_hash,
        account_limit=SIGNIN_ACCOUNT_FAILURE_LIMIT,
        ip_limit=SIGNIN_IP_FAILURE_LIMIT,
    )
    try:
        response = _cognito_client().admin_initiate_auth(
            UserPoolId=_cognito_user_pool_id(),
            ClientId=_cognito_client_id(),
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": email, "PASSWORD": password},
            ClientMetadata={"environment": ENVIRONMENT, "authProfileId": AUTH_PROFILE_ID},
        )
        result = _provider_result(
            response,
            account_hash=account_hash,
            fallback_username=email,
            allow_session=False,
        )
        final_response = (
            _new_challenge_response(result["record"])
            if result["kind"] == "challenge"
            else _new_session_response(result["authResult"], account_hash=account_hash)
        )
    except AuthV2Throttled:
        raise
    except AuthV2Unavailable:
        _release_failure_attempt(store, reservation)
        raise
    except Exception as exc:
        if _provider_unavailable(exc):
            _release_failure_attempt(store, reservation)
            raise AuthV2Unavailable() from exc
        _retain_failure_attempt(store, reservation)
        raise AuthV2AuthFailed() from exc

    _release_failure_attempt_after_success(store, reservation)
    return final_response


def _provider_result(
    response: Any,
    *,
    account_hash: str,
    fallback_username: str,
    allow_session: bool,
) -> dict[str, Any]:
    if not isinstance(response, Mapping):
        raise AuthV2Unavailable()
    challenge_name = _clean(response.get("ChallengeName"))
    if challenge_name:
        if response.get("AuthenticationResult") is not None:
            raise AuthV2Unavailable()
        if challenge_name not in _ALLOWED_CHALLENGES:
            raise AuthV2Unavailable()
        provider_session = _clean(response.get("Session"))
        parameters = response.get("ChallengeParameters")
        parameters = parameters if isinstance(parameters, Mapping) else {}
        if challenge_name == "NEW_PASSWORD_REQUIRED" and not _required_attributes_empty(
            parameters.get("requiredAttributes")
        ):
            raise AuthV2Unavailable()
        username = _clean(
            parameters.get("USER_ID_FOR_SRP")
            or parameters.get("USERNAME")
            or fallback_username
        )
        if not provider_session or not username:
            raise AuthV2Unavailable()
        return {
            "kind": "challenge",
            "record": {
                "challengeName": challenge_name,
                "cognitoSession": provider_session,
                "username": username,
                "accountHash": account_hash,
            },
        }
    auth_result = response.get("AuthenticationResult")
    if (
        not allow_session
        or not isinstance(auth_result, Mapping)
        or not _clean(auth_result.get("IdToken"))
    ):
        raise AuthV2Unavailable()
    return {"kind": "session", "authResult": dict(auth_result)}


def _required_attributes_empty(value: Any) -> bool:
    if value is None or value == "":
        return True
    parsed = value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return False
    return isinstance(parsed, list) and len(parsed) == 0


def _commit_successor(
    store: Any,
    next_item: Mapping[str, Any],
    *,
    now: int,
    source_state_hash: Optional[str] = None,
    source_record: Optional[Mapping[str, Any]] = None,
) -> None:
    if source_state_hash is None and source_record is None:
        if next_item.get("recordType") == "authSessionV2":
            store.put_session(next_item)
        else:
            _put_ephemeral(store, next_item)
        return
    if not isinstance(source_state_hash, str) or not isinstance(source_record, Mapping):
        raise AuthV2Unavailable()
    committed = store.transition_ephemeral_claim(
        source_state_hash,
        expected_type=str(source_record.get("recordType") or ""),
        expected_binding_hash=str(source_record.get("stateBindingHash") or ""),
        expected_account_hash=str(source_record.get("accountHash") or ""),
        claim_token=str(source_record.get("claimToken") or ""),
        now=now,
        next_item=next_item,
    )
    if not committed:
        raise AuthV2AuthFailed()


def _release_claim(store: Any, state_hash: str, record: Mapping[str, Any]) -> None:
    store.release_ephemeral_claim(
        state_hash,
        now=_now_epoch(),
        claim_token=str(record.get("claimToken") or ""),
        expected_binding_hash=str(record.get("stateBindingHash") or ""),
    )


def _new_challenge_response(
    record_fields: Mapping[str, Any],
    *,
    clear_enrollment: bool = False,
    store: Any = None,
    source_state_hash: Optional[str] = None,
    source_record: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    state_value = _random_urlsafe(32)
    csrf_value = _random_urlsafe(32)
    now = _now_epoch()
    record = {
        "recordType": "authChallengeV2",
        "stateIdHash": _sha256(state_value),
        "csrfHash": _sha256(csrf_value),
        "scope": deepcopy(_SCOPE),
        "accountHash": str(record_fields["accountHash"]),
        "username": str(record_fields["username"]),
        "challengeName": str(record_fields["challengeName"]),
        "cognitoSession": str(record_fields["cognitoSession"]),
        "createdAt": now,
        "expiresAt": now + STATE_SECONDS,
        "claimedAt": None,
    }
    record["stateBindingHash"] = _ephemeral_state_binding_hash(record)
    _commit_successor(
        store or _session_store(),
        record,
        now=now,
        source_state_hash=source_state_hash,
        source_record=source_record,
    )
    cookies = [
        _cookie(CHALLENGE_COOKIE_NAME, state_value, http_only=True, max_age=STATE_SECONDS),
        _cookie(
            CHALLENGE_CSRF_COOKIE_NAME,
            csrf_value,
            http_only=False,
            max_age=STATE_SECONDS,
        ),
    ]
    if clear_enrollment:
        cookies.extend(
            [
                _cookie(MFA_ENROLLMENT_COOKIE_NAME, "", http_only=True, max_age=0),
                _cookie(
                    MFA_ENROLLMENT_CSRF_COOKIE_NAME,
                    "",
                    http_only=False,
                    max_age=0,
                ),
            ]
        )
    return _json_response(
        200,
        {"ok": True, "status": "challenge-required", "challengeName": record["challengeName"]},
        cookies=cookies,
    )


def _challenge_response(event: dict[str, Any]) -> dict[str, Any]:
    payload = _payload(event, auth_failure=True)
    _cognito_configuration()
    store = _session_store()
    state_hash, record = _claim_ephemeral(
        event,
        store,
        cookie_name=CHALLENGE_COOKIE_NAME,
        csrf_cookie_name=CHALLENGE_CSRF_COOKIE_NAME,
        expected_type="authChallengeV2",
    )
    claim_token = str(record["claimToken"])
    reservation: Any = None
    try:
        reservation = _begin_failure_attempt(
            store,
            operation="challenge",
            account_hash=str(record["accountHash"]),
            ip_hash=_sha256(_source_ip(event)),
            account_limit=CHALLENGE_ACCOUNT_FAILURE_LIMIT,
            ip_limit=CHALLENGE_IP_FAILURE_LIMIT,
        )
        challenge_name = str(record["challengeName"])
        challenge_responses = {"USERNAME": str(record["username"])}
        if challenge_name == "SOFTWARE_TOKEN_MFA":
            challenge_responses["SOFTWARE_TOKEN_MFA_CODE"] = _totp(payload.get("code"))
        elif challenge_name == "NEW_PASSWORD_REQUIRED":
            challenge_responses["NEW_PASSWORD"] = _password(payload.get("newPassword"))
        else:
            raise AuthV2AuthFailed()
        response = _cognito_client().admin_respond_to_auth_challenge(
            UserPoolId=_cognito_user_pool_id(),
            ClientId=_cognito_client_id(),
            ChallengeName=challenge_name,
            Session=str(record["cognitoSession"]),
            ChallengeResponses=challenge_responses,
        )
        result = _provider_result(
            response,
            account_hash=str(record["accountHash"]),
            fallback_username=str(record["username"]),
            allow_session=challenge_name == "SOFTWARE_TOKEN_MFA",
        )
    except AuthV2Throttled:
        _release_claim(store, state_hash, record)
        raise
    except AuthV2Unavailable:
        _release_failure_attempt(store, reservation)
        _release_claim(store, state_hash, record)
        raise
    except Exception as exc:
        if _provider_unavailable(exc):
            _release_failure_attempt(store, reservation)
            _release_claim(store, state_hash, record)
            raise AuthV2Unavailable() from exc
        _retain_failure_attempt(store, reservation)
        _release_claim(store, state_hash, record)
        raise AuthV2AuthFailed() from exc

    try:
        final_response = (
            _new_challenge_response(
                result["record"],
                store=store,
                source_state_hash=state_hash,
                source_record=record,
            )
            if result["kind"] == "challenge"
            else _new_session_response(
                result["authResult"],
                account_hash=str(record["accountHash"]),
                clear_challenge=True,
                store=store,
                source_state_hash=state_hash,
                source_record=record,
            )
        )
    except AuthV2Unavailable:
        _release_failure_attempt(store, reservation)
        raise
    except Exception as exc:
        _retain_failure_attempt(store, reservation)
        raise AuthV2AuthFailed() from exc
    _release_failure_attempt_after_success(store, reservation)
    return final_response


def _mfa_setup_response(event: dict[str, Any]) -> dict[str, Any]:
    _cognito_configuration()
    store = _session_store()
    state_hash, record = _claim_ephemeral(
        event,
        store,
        cookie_name=CHALLENGE_COOKIE_NAME,
        csrf_cookie_name=CHALLENGE_CSRF_COOKIE_NAME,
        expected_type="authChallengeV2",
        expected_challenge="MFA_SETUP",
    )
    claim_token = str(record["claimToken"])
    reservation: Any = None
    try:
        reservation = _begin_failure_attempt(
            store,
            operation="challenge",
            account_hash=str(record["accountHash"]),
            ip_hash=_sha256(_source_ip(event)),
            account_limit=CHALLENGE_ACCOUNT_FAILURE_LIMIT,
            ip_limit=CHALLENGE_IP_FAILURE_LIMIT,
        )
        provider = _cognito_client().associate_software_token(
            Session=str(record["cognitoSession"])
        )
        secret_code = _clean(provider.get("SecretCode") if isinstance(provider, Mapping) else "")
        provider_session = _clean(provider.get("Session") if isinstance(provider, Mapping) else "")
        if not secret_code or not provider_session:
            raise AuthV2Unavailable()
    except AuthV2Throttled:
        _release_claim(store, state_hash, record)
        raise
    except AuthV2Unavailable:
        _release_failure_attempt(store, reservation)
        _release_claim(store, state_hash, record)
        raise
    except Exception as exc:
        if _provider_unavailable(exc):
            _release_failure_attempt(store, reservation)
            _release_claim(store, state_hash, record)
            raise AuthV2Unavailable() from exc
        _retain_failure_attempt(store, reservation)
        _release_claim(store, state_hash, record)
        raise AuthV2AuthFailed() from exc

    enrollment_value = _random_urlsafe(32)
    csrf_value = _random_urlsafe(32)
    now = _now_epoch()
    enrollment = {
        "recordType": "authMfaEnrollmentV2",
        "stateIdHash": _sha256(enrollment_value),
        "csrfHash": _sha256(csrf_value),
        "scope": deepcopy(_SCOPE),
        "accountHash": str(record["accountHash"]),
        "username": str(record["username"]),
        "cognitoSession": provider_session,
        "createdAt": now,
        "expiresAt": now + STATE_SECONDS,
        "claimedAt": None,
    }
    enrollment["stateBindingHash"] = _ephemeral_state_binding_hash(enrollment)
    try:
        _commit_successor(
            store,
            enrollment,
            now=now,
            source_state_hash=state_hash,
            source_record=record,
        )
    except (AuthV2AuthFailed, AuthV2Unavailable):
        _release_failure_attempt(store, reservation)
        raise
    _release_failure_attempt_after_success(store, reservation)
    return _json_response(
        200,
        {
            "ok": True,
            "status": "mfa-enrollment-required",
            "mfa": {
                "method": "SOFTWARE_TOKEN_MFA",
                "issuer": "The Hair Narrative",
                "accountLabel": "Journal owner",
                "manualSetupKey": secret_code,
            },
        },
        cookies=[
            _cookie(MFA_ENROLLMENT_COOKIE_NAME, enrollment_value, http_only=True, max_age=STATE_SECONDS),
            _cookie(MFA_ENROLLMENT_CSRF_COOKIE_NAME, csrf_value, http_only=False, max_age=STATE_SECONDS),
            _cookie(CHALLENGE_COOKIE_NAME, "", http_only=True, max_age=0),
            _cookie(CHALLENGE_CSRF_COOKIE_NAME, "", http_only=False, max_age=0),
        ],
    )


def _mfa_verify_response(event: dict[str, Any]) -> dict[str, Any]:
    payload = _payload(event, auth_failure=True)
    _cognito_configuration()
    store = _session_store()
    state_hash, record = _claim_ephemeral(
        event,
        store,
        cookie_name=MFA_ENROLLMENT_COOKIE_NAME,
        csrf_cookie_name=MFA_ENROLLMENT_CSRF_COOKIE_NAME,
        expected_type="authMfaEnrollmentV2",
    )
    claim_token = str(record["claimToken"])
    reservation: Any = None
    try:
        reservation = _begin_failure_attempt(
            store,
            operation="challenge",
            account_hash=str(record["accountHash"]),
            ip_hash=_sha256(_source_ip(event)),
            account_limit=CHALLENGE_ACCOUNT_FAILURE_LIMIT,
            ip_limit=CHALLENGE_IP_FAILURE_LIMIT,
        )
        verified = _cognito_client().verify_software_token(
            Session=str(record["cognitoSession"]),
            UserCode=_totp(payload.get("code")),
            FriendlyDeviceName="The Hair Narrative",
        )
        if _clean(verified.get("Status") if isinstance(verified, Mapping) else "") != "SUCCESS":
            raise AuthV2Unavailable()
        provider_session = _clean(
            verified.get("Session") if isinstance(verified, Mapping) else ""
        )
        if not provider_session:
            raise AuthV2Unavailable()
        response = _cognito_client().admin_respond_to_auth_challenge(
            UserPoolId=_cognito_user_pool_id(),
            ClientId=_cognito_client_id(),
            ChallengeName="MFA_SETUP",
            Session=provider_session,
            ChallengeResponses={"USERNAME": str(record["username"])},
        )
        result = _provider_result(
            response,
            account_hash=str(record["accountHash"]),
            fallback_username=str(record["username"]),
            allow_session=True,
        )
    except AuthV2Throttled:
        _release_claim(store, state_hash, record)
        raise
    except AuthV2Unavailable:
        _release_failure_attempt(store, reservation)
        _release_claim(store, state_hash, record)
        raise
    except Exception as exc:
        if _provider_unavailable(exc):
            _release_failure_attempt(store, reservation)
            _release_claim(store, state_hash, record)
            raise AuthV2Unavailable() from exc
        _retain_failure_attempt(store, reservation)
        _release_claim(store, state_hash, record)
        raise AuthV2AuthFailed() from exc

    try:
        final_response = (
            _new_challenge_response(
                result["record"],
                clear_enrollment=True,
                store=store,
                source_state_hash=state_hash,
                source_record=record,
            )
            if result["kind"] == "challenge"
            else _new_session_response(
                result["authResult"],
                account_hash=str(record["accountHash"]),
                clear_enrollment=True,
                store=store,
                source_state_hash=state_hash,
                source_record=record,
            )
        )
    except AuthV2Unavailable:
        _release_failure_attempt(store, reservation)
        raise
    except AuthV2AuthFailed:
        _release_failure_attempt(store, reservation)
        raise
    except Exception as exc:
        _release_failure_attempt(store, reservation)
        raise AuthV2Unavailable() from exc
    _release_failure_attempt_after_success(store, reservation)
    return final_response


def _new_session_response(
    auth_result: Mapping[str, Any],
    *,
    account_hash: str,
    clear_challenge: bool = False,
    clear_enrollment: bool = False,
    store: Any = None,
    source_state_hash: Optional[str] = None,
    source_record: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    token = _clean(auth_result.get("IdToken"))
    if not token:
        raise AuthV2Unavailable()
    try:
        claims = _verify_id_token(token)
        subject = _clean(claims.get("sub"))
        if not subject or _clean(claims.get("token_use")) != "id":
            raise AuthV2AuthFailed()
        state = _state_for_subject(subject)
        if (
            state.get("enabled") is not True
            or state.get("accountPurpose") not in {"qa", "client-owner"}
            or type(state.get("sessionVersion")) is not int
            or int(state["sessionVersion"]) < 1
        ):
            raise AuthV2AuthFailed()
    except AuthV2AuthFailed:
        raise
    except (AuthV2Unavailable, CurrentUserStateUnavailable) as exc:
        raise AuthV2Unavailable() from exc
    except Exception as exc:
        raise AuthV2Unavailable() from exc

    session_value = _random_urlsafe(32)
    csrf_value = _random_urlsafe(32)
    now = _now_epoch()
    absolute_expires_at = now + SESSION_ABSOLUTE_SECONDS
    roles = claims.get("cognito:groups")
    raw_cognito_username = claims.get("cognito:username")
    cognito_username = (
        str(raw_cognito_username) if _valid_cognito_username(raw_cognito_username) else ""
    )
    if state["accountPurpose"] == "client-owner":
        if roles != [AUTH_PROFILE_ID] or not cognito_username:
            raise AuthV2AuthFailed()
    roles = [str(role) for role in roles] if isinstance(roles, list) else []
    record = {
        "recordType": "authSessionV2",
        "sessionIdHash": _sha256(session_value),
        "csrfHash": _sha256(csrf_value),
        "scope": deepcopy(_SCOPE),
        "subject": subject,
        "accountHash": account_hash,
        "accountPurpose": state["accountPurpose"],
        "sessionVersion": state["sessionVersion"],
        "roles": roles,
        "createdAt": now,
        "lastSeenAt": now,
        "idleExpiresAt": now + SESSION_IDLE_SECONDS,
        "absoluteExpiresAt": absolute_expires_at,
        "expiresAt": absolute_expires_at,
        "revokedAt": None,
    }
    if cognito_username:
        record["cognitoUsername"] = cognito_username
    _require_current_owner_membership(record)
    try:
        _commit_successor(
            store or _session_store(),
            record,
            now=now,
            source_state_hash=source_state_hash,
            source_record=source_record,
        )
    except AuthV2Unavailable:
        raise
    except Exception as exc:
        raise AuthV2Unavailable() from exc
    cookies = [
        _cookie(
            SESSION_COOKIE_NAME,
            session_value,
            http_only=True,
            max_age=SESSION_ABSOLUTE_SECONDS,
        ),
        _cookie(
            CSRF_COOKIE_NAME,
            csrf_value,
            http_only=False,
            max_age=SESSION_ABSOLUTE_SECONDS,
        ),
    ]
    if clear_challenge:
        cookies.extend(
            [
                _cookie(CHALLENGE_COOKIE_NAME, "", http_only=True, max_age=0),
                _cookie(CHALLENGE_CSRF_COOKIE_NAME, "", http_only=False, max_age=0),
            ]
        )
    if clear_enrollment:
        cookies.extend(
            [
                _cookie(MFA_ENROLLMENT_COOKIE_NAME, "", http_only=True, max_age=0),
                _cookie(MFA_ENROLLMENT_CSRF_COOKIE_NAME, "", http_only=False, max_age=0),
            ]
        )
    return _json_response(200, _public_session_payload(record), cookies=cookies)


def _state_for_subject(subject: str) -> dict[str, Any]:
    """Load a fresh state once without accepting purpose/version from the browser."""

    from auth_admin_current_user_v2 import load_current_user_state

    return load_current_user_state(
        _current_user_client(), scope=APPROVED_SCOPE, subject=subject
    )


def _put_ephemeral(store: Any, record: Mapping[str, Any]) -> None:
    try:
        store.put_ephemeral(record)
    except AuthV2Unavailable:
        raise
    except Exception as exc:
        raise AuthV2Unavailable() from exc


def _require_active_service_binding() -> dict[str, Any]:
    """Fence every v2 route with the authoritative, exact-key registry row."""

    from service_binding_registry_consumer_v2 import (
        ServiceBindingUnavailable,
        load_active_service_binding,
    )

    try:
        return load_active_service_binding(
            _service_binding_registry_client(),
            expected_descriptor=_service_binding_expected_descriptor(),
            trusted_resource_scope=_service_binding_trusted_resource_scope(),
        )
    except ServiceBindingUnavailable as exc:
        raise AuthV2Unavailable() from exc
    except AuthV2Unavailable:
        raise
    except Exception as exc:
        raise AuthV2Unavailable() from exc


def _service_binding_registry_client() -> Any:
    return _dynamodb_client()


def _service_binding_expected_descriptor() -> dict[str, str]:
    values = {
        "descriptorVersionId": _clean(
            os.getenv("THN_AUTH_V2_DESCRIPTOR_VERSION_ID")
        ),
        "descriptorSha256": _clean(os.getenv("THN_AUTH_V2_DESCRIPTOR_SHA256")),
        "authPolicyVersion": _clean(
            os.getenv("THN_AUTH_V2_AUTH_POLICY_VERSION")
        ),
    }
    if not all(values.values()):
        raise AuthV2Unavailable()
    return values


def _service_binding_trusted_resource_scope() -> dict[str, str]:
    values = {
        "partition": _clean(os.getenv("THN_AUTH_V2_AWS_PARTITION")),
        "accountId": _clean(os.getenv("THN_AUTH_V2_AWS_ACCOUNT_ID")),
        "region": _clean(os.getenv("THN_AUTH_V2_AWS_REGION")),
    }
    if not all(values.values()):
        raise AuthV2Unavailable()
    return values


def _require_session(event: Mapping[str, Any], *, touch: bool) -> dict[str, Any]:
    session_value = _single_cookie_value(event, SESSION_COOKIE_NAME)
    if not session_value:
        raise AuthV2SessionRequired()
    store = _session_store()
    session_hash = _sha256(session_value)
    try:
        session = store.get_session(session_hash, consistent_read=True)
    except AuthV2Unavailable:
        raise
    except Exception as exc:
        raise AuthV2Unavailable() from exc
    now = _now_epoch()
    if not _valid_session_record(session, now=now):
        raise AuthV2SessionRequired()
    try:
        assert_session_current(
            _current_user_client(),
            scope=APPROVED_SCOPE,
            subject=str(session["subject"]),
            account_purpose=str(session["accountPurpose"]),
            session_version=int(session["sessionVersion"]),
        )
    except CurrentUserSessionStale as exc:
        raise AuthV2SessionRequired() from exc
    except CurrentUserStateUnavailable as exc:
        raise AuthV2Unavailable() from exc
    except (ValueError, TypeError) as exc:
        raise AuthV2SessionRequired() from exc
    _require_current_owner_membership(session)
    if not touch:
        return session
    idle_expires_at = min(
        now + SESSION_IDLE_SECONDS, int(session["absoluteExpiresAt"])
    )
    try:
        return store.touch_session(
            session_hash,
            now=now,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=int(session["absoluteExpiresAt"]),
            subject=str(session["subject"]),
            account_purpose=str(session["accountPurpose"]),
            session_version=int(session["sessionVersion"]),
        )
    except AuthV2Unavailable:
        raise
    except CurrentUserSessionStale as exc:
        raise AuthV2SessionRequired() from exc
    except Exception as exc:
        if not _conditional_check_failed(exc):
            raise AuthV2Unavailable() from exc
        raise AuthV2SessionRequired() from exc


def _valid_session_record(value: Any, *, now: int) -> bool:
    if not isinstance(value, Mapping):
        return False
    try:
        roles = value.get("roles")
        timestamps = (
            value.get("createdAt"),
            value.get("lastSeenAt"),
            value.get("idleExpiresAt"),
            value.get("absoluteExpiresAt"),
            value.get("expiresAt"),
        )
        account_purpose = value.get("accountPurpose")
        owner_membership_shape_is_valid = (
            account_purpose != "client-owner"
            or (
                roles == [AUTH_PROFILE_ID]
                and _valid_cognito_username(value.get("cognitoUsername"))
            )
        )
        return (
            value.get("recordType") == "authSessionV2"
            and value.get("scope") == _SCOPE
            and value.get("revokedAt") is None
            and _hex_hash(value.get("sessionIdHash"))
            and _hex_hash(value.get("csrfHash"))
            and _hex_hash(value.get("accountHash"))
            and isinstance(value.get("subject"), str)
            and bool(value.get("subject"))
            and account_purpose in {"qa", "client-owner"}
            and type(value.get("sessionVersion")) is int
            and int(value["sessionVersion"]) >= 1
            and isinstance(roles, list)
            and all(isinstance(role, str) and role for role in roles)
            and owner_membership_shape_is_valid
            and all(type(timestamp) is int for timestamp in timestamps)
            and 0 <= int(value["createdAt"]) <= int(value["lastSeenAt"])
            and int(value["lastSeenAt"]) <= int(value["idleExpiresAt"])
            and int(value["idleExpiresAt"])
            <= int(value["lastSeenAt"]) + SESSION_IDLE_SECONDS
            and int(value["idleExpiresAt"]) <= int(value["absoluteExpiresAt"])
            and int(value["absoluteExpiresAt"])
            <= int(value["createdAt"]) + SESSION_ABSOLUTE_SECONDS
            and int(value["absoluteExpiresAt"]) == int(value["expiresAt"])
            and int(value["idleExpiresAt"]) > now
            and int(value["absoluteExpiresAt"]) > now
        )
    except (ValueError, TypeError):
        return False


def _require_current_owner_membership(session: Mapping[str, Any]) -> None:
    """Fail closed when the dedicated owner's Cognito membership has drifted."""

    if session.get("accountPurpose") != "client-owner":
        return
    username = session.get("cognitoUsername")
    subject = session.get("subject")
    if not isinstance(username, str) or not username or not isinstance(subject, str):
        raise AuthV2SessionRequired()
    try:
        cognito = _cognito_client()
        response = cognito.admin_get_user(
            UserPoolId=_cognito_user_pool_id(),
            Username=username,
        )
        if not isinstance(response, Mapping):
            raise AuthV2Unavailable()
        attributes = response.get("UserAttributes")
        if not isinstance(attributes, list):
            raise AuthV2Unavailable()
        subjects = [
            item.get("Value")
            for item in attributes
            if isinstance(item, Mapping) and item.get("Name") == "sub"
        ]
        if (
            response.get("Username") != username
            or response.get("Enabled") is not True
            or subjects != [subject]
        ):
            raise AuthV2SessionRequired()

        groups: list[Any] = []
        next_token = ""
        seen_tokens: set[str] = set()
        while True:
            arguments: dict[str, Any] = {
                "UserPoolId": _cognito_user_pool_id(),
                "Username": username,
                "Limit": 60,
            }
            if next_token:
                arguments["NextToken"] = next_token
            group_response = cognito.admin_list_groups_for_user(**arguments)
            if not isinstance(group_response, Mapping):
                raise AuthV2Unavailable()
            page = group_response.get("Groups")
            if not isinstance(page, list) or any(
                not isinstance(item, Mapping) for item in page
            ):
                raise AuthV2Unavailable()
            groups.extend(page)
            next_token = _clean(group_response.get("NextToken"))
            if not next_token:
                break
            if next_token in seen_tokens:
                raise AuthV2Unavailable()
            seen_tokens.add(next_token)
        if [group.get("GroupName") for group in groups] != [AUTH_PROFILE_ID]:
            raise AuthV2SessionRequired()
    except (AuthV2SessionRequired, AuthV2Unavailable):
        raise
    except Exception as exc:
        if _aws_error_code(exc) in {"NotAuthorizedException", "UserNotFoundException"}:
            raise AuthV2SessionRequired() from exc
        raise AuthV2Unavailable() from exc


def _logout_response(event: dict[str, Any]) -> dict[str, Any]:
    session = _require_session(event, touch=False)
    _require_csrf(
        event,
        cookie_name=CSRF_COOKIE_NAME,
        expected_hash=str(session["csrfHash"]),
    )
    if not _session_store().revoke_session(
        str(session["sessionIdHash"]), now=_now_epoch()
    ):
        raise AuthV2Unavailable()
    return _json_response(
        200,
        {"ok": True, "status": "signed-out"},
        cookies=_clear_all_v2_cookies(),
    )


def _claim_ephemeral(
    event: Mapping[str, Any],
    store: Any,
    *,
    cookie_name: str,
    csrf_cookie_name: str,
    expected_type: str,
    expected_challenge: Optional[str] = None,
) -> tuple[str, dict[str, Any]]:
    raw_state = _single_cookie_value(event, cookie_name)
    if not raw_state:
        raise AuthV2AuthFailed()
    state_hash = _sha256(raw_state)
    try:
        record = store.get_ephemeral(state_hash, consistent_read=True)
    except AuthV2Unavailable:
        raise
    except Exception as exc:
        raise AuthV2Unavailable() from exc
    now = _now_epoch()
    if (
        not _valid_ephemeral_record(record, expected_type=expected_type, now=now)
        or record.get("claimedAt") is not None
    ):
        raise AuthV2AuthFailed()
    if expected_challenge and record.get("challengeName") != expected_challenge:
        raise AuthV2AuthFailed()
    _require_csrf(
        event,
        cookie_name=csrf_cookie_name,
        expected_hash=str(record.get("csrfHash") or ""),
    )
    claimed = store.claim_ephemeral(
        state_hash,
        expected_type=expected_type,
        expected_binding_hash=str(record["stateBindingHash"]),
        now=now,
    )
    if claimed is None:
        raise AuthV2AuthFailed()
    if (
        not _valid_ephemeral_record(
            claimed,
            expected_type=expected_type,
            expected_binding_hash=str(record["stateBindingHash"]),
            now=now,
        )
        or not _clean(claimed.get("claimToken"))
        or claimed.get("claimedAt") != now
    ):
        claim_token = _clean(claimed.get("claimToken")) if isinstance(claimed, Mapping) else ""
        if claim_token:
            try:
                store.release_ephemeral_claim(
                    state_hash,
                    now=now,
                    claim_token=claim_token,
                    expected_binding_hash=str(record["stateBindingHash"]),
                )
            except Exception:
                _safe_log(
                    "warning",
                    "Unable to release an invalid ephemeral claim response.",
                    code="auth_v2_invalid_claim_release_failed",
                )
        raise AuthV2Unavailable()
    if expected_challenge and claimed.get("challengeName") != expected_challenge:
        raise AuthV2AuthFailed()
    return state_hash, dict(claimed)


def _begin_failure_attempt(
    store: Any,
    *,
    operation: str,
    account_hash: str,
    ip_hash: str,
    account_limit: int,
    ip_limit: int,
) -> Any:
    now = _now_epoch()
    reserve = getattr(store, "reserve_failure_attempt", None)
    if callable(reserve):
        return reserve(
            operation,
            account_hash,
            ip_hash,
            now=now,
            window_seconds=FAILURE_WINDOW_SECONDS,
            account_limit=account_limit,
            ip_limit=ip_limit,
        )
    if store.count_failures(
        operation,
        "account",
        account_hash,
        now=now,
        window_seconds=FAILURE_WINDOW_SECONDS,
    ) >= account_limit:
        raise AuthV2Throttled()
    if store.count_failures(
        operation,
        "ip",
        ip_hash,
        now=now,
        window_seconds=FAILURE_WINDOW_SECONDS,
    ) >= ip_limit:
        raise AuthV2Throttled()
    return {
        "mode": "deferred",
        "operation": operation,
        "accountHash": account_hash,
        "ipHash": ip_hash,
        "now": now,
    }


def _retain_failure_attempt(store: Any, reservation: Any) -> None:
    if not isinstance(reservation, Mapping):
        return
    if reservation.get("mode") != "deferred":
        return
    for dimension, field in (("account", "accountHash"), ("ip", "ipHash")):
        store.record_failure(
            str(reservation["operation"]),
            dimension,
            str(reservation[field]),
            now=int(reservation["now"]),
            window_seconds=FAILURE_WINDOW_SECONDS,
        )


def _release_failure_attempt(store: Any, reservation: Any) -> None:
    if not isinstance(reservation, Mapping) or reservation.get("mode") == "deferred":
        return
    release = getattr(store, "release_failure_attempt", None)
    if callable(release):
        release(reservation, now=_now_epoch())


def _release_failure_attempt_after_success(store: Any, reservation: Any) -> None:
    """Keep an already-committed auth transition usable if cleanup is unavailable."""

    try:
        _release_failure_attempt(store, reservation)
    except Exception:
        _safe_log(
            "WARNING",
            "Auth Admin v2 throttle cleanup deferred",
            code="throttle_cleanup_deferred",
        )


def _public_session_payload(session: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "status": "signed-in",
        "account": {
            "accountPurpose": session["accountPurpose"],
            "roles": list(session.get("roles") or []),
        },
        "session": {
            "idleExpiresAt": int(session["idleExpiresAt"]),
            "absoluteExpiresAt": int(session["absoluteExpiresAt"]),
        },
    }


def _require_admin_origin(event: Mapping[str, Any]) -> None:
    request_context = event.get("requestContext")
    request_context = request_context if isinstance(request_context, Mapping) else {}
    authorizer = request_context.get("authorizer")
    authorizer = authorizer if isinstance(authorizer, Mapping) else {}
    authorizer_context = authorizer.get("lambda")
    authorizer_context = (
        authorizer_context if isinstance(authorizer_context, Mapping) else {}
    )
    if authorizer_context.get("originVerified") is not True:
        raise AuthV2OriginDenied()
    # CloudFront preserves the verified viewer host in x-forwarded-host because
    # API Gateway requires its own execute-api hostname at the origin.  The
    # authorizer context above proves this request crossed the private edge.
    forwarded_host = _header(event, "x-forwarded-host")
    if forwarded_host != ADMIN_HOST:
        raise AuthV2OriginDenied()
    origin = _header(event, "origin")
    if (_method(event) not in {"GET", "HEAD"} and origin != ADMIN_ORIGIN) or (
        origin and origin != ADMIN_ORIGIN
    ):
        raise AuthV2OriginDenied()


def _require_csrf(
    event: Mapping[str, Any], *, cookie_name: str, expected_hash: str
) -> None:
    cookie_value = _single_cookie_value(event, cookie_name)
    header_value = _header(event, CSRF_HEADER_NAME)
    if (
        not cookie_value
        or not header_value
        or not hmac.compare_digest(cookie_value, header_value)
        or not hmac.compare_digest(_sha256(cookie_value), expected_hash)
    ):
        raise AuthV2CsrfDenied()


def _clear_all_v2_cookies() -> list[str]:
    return [
        _cookie(SESSION_COOKIE_NAME, "", http_only=True, max_age=0),
        _cookie(CSRF_COOKIE_NAME, "", http_only=False, max_age=0),
        _cookie(CHALLENGE_COOKIE_NAME, "", http_only=True, max_age=0),
        _cookie(CHALLENGE_CSRF_COOKIE_NAME, "", http_only=False, max_age=0),
        _cookie(MFA_ENROLLMENT_COOKIE_NAME, "", http_only=True, max_age=0),
        _cookie(MFA_ENROLLMENT_CSRF_COOKIE_NAME, "", http_only=False, max_age=0),
    ]


def _payload(event: Mapping[str, Any], *, auth_failure: bool) -> dict[str, Any]:
    try:
        raw: Any = event.get("body")
        if event.get("isBase64Encoded") is True and isinstance(raw, str):
            raw = base64.b64decode(raw, validate=True).decode("utf-8")
        if raw in {None, ""}:
            return {}
        value = json.loads(str(raw))
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value
    except Exception as exc:
        if auth_failure:
            raise AuthV2AuthFailed() from exc
        raise


def _method(event: Mapping[str, Any]) -> str:
    context = event.get("requestContext")
    context = context if isinstance(context, Mapping) else {}
    http = context.get("http")
    http = http if isinstance(http, Mapping) else {}
    return _clean(http.get("method") or event.get("httpMethod")).upper()


def _path(event: Mapping[str, Any]) -> str:
    context = event.get("requestContext")
    context = context if isinstance(context, Mapping) else {}
    http = context.get("http")
    http = http if isinstance(http, Mapping) else {}
    return _clean(event.get("rawPath") or event.get("path") or http.get("path")) or "/"


def _header(event: Mapping[str, Any], name: str) -> str:
    headers = event.get("headers")
    headers = headers if isinstance(headers, Mapping) else {}
    matches = [
        _clean(value)
        for key, value in headers.items()
        if str(key).lower() == name.lower()
    ]
    return matches[0] if len(matches) == 1 else ""


def _single_cookie_value(event: Mapping[str, Any], name: str) -> str:
    pairs: list[str] = []
    cookies = event.get("cookies")
    if isinstance(cookies, list):
        pairs.extend(str(cookie) for cookie in cookies if isinstance(cookie, str))
    header = _header(event, "cookie")
    if header:
        pairs.extend(part.strip() for part in header.split(";"))
    values: list[str] = []
    for pair in pairs:
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        if key.strip() == name:
            values.append(value.strip())
    return values[0] if len(values) == 1 else ""


def _source_ip(event: Mapping[str, Any]) -> str:
    context = event.get("requestContext")
    context = context if isinstance(context, Mapping) else {}
    authorizer = context.get("authorizer")
    authorizer = authorizer if isinstance(authorizer, Mapping) else {}
    authorizer_context = authorizer.get("lambda")
    authorizer_context = (
        authorizer_context if isinstance(authorizer_context, Mapping) else {}
    )
    raw = _clean(authorizer_context.get("viewerIp"))
    if not raw:
        raise AuthV2AuthFailed()
    try:
        parsed = ipaddress.ip_address(raw).compressed
        if not hmac.compare_digest(parsed, raw):
            raise ValueError("viewer IP is not canonical")
        return parsed
    except ValueError as exc:
        raise AuthV2AuthFailed() from exc


def _email(value: Any) -> str:
    result = _clean(value).lower()
    if not result or len(result) > 320 or not _EMAIL_RE.fullmatch(result):
        raise ValueError("invalid account")
    return result


def _password(value: Any) -> str:
    result = str(value or "")
    if not result or len(result) > 4096 or any(ord(char) < 32 for char in result):
        raise ValueError("invalid password")
    return result


def _totp(value: Any) -> str:
    result = _clean(value)
    if not _TOTP_RE.fullmatch(result):
        raise ValueError("invalid code")
    return result


def _json_response(
    status_code: int,
    payload: Mapping[str, Any],
    *,
    cookies: Optional[list[str]] = None,
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "statusCode": status_code,
        "headers": {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store, max-age=0",
            "pragma": "no-cache",
            "expires": "0",
            "referrer-policy": "no-referrer",
            "x-content-type-options": "nosniff",
            "access-control-allow-origin": ADMIN_ORIGIN,
            "access-control-allow-credentials": "true",
            "vary": "Origin",
        },
        "body": json.dumps(dict(payload), separators=(",", ":")),
    }
    if cookies:
        response["cookies"] = cookies
    return response


def _cookie(name: str, value: str, *, http_only: bool, max_age: int) -> str:
    parts = [f"{name}={value}"]
    if http_only:
        parts.append("HttpOnly")
    parts.extend(["Secure", "SameSite=Lax", "Path=/", f"Max-Age={max_age}"])
    return "; ".join(parts)


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _valid_cognito_username(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value == value.strip()
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _now_epoch() -> int:
    return int(time.time())


def _random_urlsafe(byte_count: int = 32) -> str:
    return secrets.token_urlsafe(byte_count)


def _cognito_configuration() -> tuple[str, str, str]:
    region = _clean(os.getenv("THN_AUTH_V2_COGNITO_REGION"))
    user_pool_id = _clean(os.getenv("THN_AUTH_V2_COGNITO_USER_POOL_ID"))
    client_id = _clean(os.getenv("THN_AUTH_V2_COGNITO_CLIENT_ID"))
    if (
        re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]", region) is None
        or re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]_[A-Za-z0-9]+", user_pool_id)
        is None
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", client_id) is None
    ):
        raise AuthV2Unavailable()
    return region, user_pool_id, client_id


def _cognito_client_id() -> str:
    return _cognito_configuration()[2]


def _cognito_user_pool_id() -> str:
    return _cognito_configuration()[1]


def _verify_id_token(token: str) -> dict[str, Any]:
    region, user_pool_id, client_id = _cognito_configuration()
    issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
    try:
        import jwt  # type: ignore
        from jwt import PyJWKClient  # type: ignore

        signing_key = PyJWKClient(f"{issuer}/.well-known/jwks.json").get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=issuer,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub", "token_use"],
                "strict_aud": True,
            },
        )
    except Exception as exc:
        if _provider_unavailable(exc):
            raise AuthV2Unavailable() from exc
        raise AuthV2AuthFailed() from exc
    if not isinstance(claims, Mapping) or _clean(claims.get("token_use")) != "id":
        raise AuthV2AuthFailed()
    return dict(claims)


def _session_store() -> Any:
    return DynamoAuthV2Store(_dynamodb_client())


def _current_user_client() -> Any:
    return _dynamodb_client()


def _cognito_client() -> Any:
    import boto3  # type: ignore

    return boto3.client("cognito-idp")


def _dynamodb_client() -> Any:
    import boto3  # type: ignore

    return boto3.client("dynamodb")


def _safe_log(level: str, message: str, *, code: str) -> None:
    print(json.dumps({"level": level, "message": message, "code": code}, separators=(",", ":")))


def _aws_error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return ""
    error = response.get("Error")
    if not isinstance(error, Mapping):
        return ""
    code = error.get("Code")
    return code if isinstance(code, str) else ""


def _provider_unavailable(exc: BaseException) -> bool:
    current: Optional[BaseException] = exc
    seen: set[int] = set()
    unavailable_names = {
        "ConnectTimeoutError",
        "ConnectionClosedError",
        "EndpointConnectionError",
        "PyJWKClientConnectionError",
        "ReadTimeoutError",
    }
    unavailable_codes = {
        "InternalErrorException",
        "ServiceUnavailableException",
        "ThrottlingException",
        "TooManyRequestsException",
    }
    while isinstance(current, BaseException) and id(current) not in seen:
        seen.add(id(current))
        if (
            isinstance(current, AuthV2Unavailable)
            or _aws_error_code(current) in unavailable_codes
            or current.__class__.__name__ in unavailable_names
        ):
            return True
        cause = current.__cause__
        current = cause if isinstance(cause, BaseException) else current.__context__
    return False


def _conditional_check_failed(exc: BaseException) -> bool:
    code = _aws_error_code(exc)
    return (
        code == "ConditionalCheckFailedException"
        or exc.__class__.__name__ == "ConditionalCheckFailedException"
        or str(exc) == "ConditionalCheckFailedException"
    )


def _transaction_canceled_by_condition_only(
    exc: BaseException, *, expected_item_count: int
) -> bool:
    if _aws_error_code(exc) != "TransactionCanceledException":
        return False
    if type(expected_item_count) is not int or expected_item_count < 1:
        return False
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return False
    reasons = response.get("CancellationReasons")
    if not isinstance(reasons, list) or len(reasons) != expected_item_count:
        return False
    codes: list[str] = []
    for reason in reasons:
        if not isinstance(reason, Mapping):
            return False
        code = reason.get("Code")
        if not isinstance(code, str):
            return False
        if code not in {"None", "ConditionalCheckFailed"}:
            return False
        codes.append(code)
    return "ConditionalCheckFailed" in codes


def _hex_hash(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _ephemeral_state_binding_hash(record: Mapping[str, Any]) -> str:
    """Bind the immutable authorization state used by every claim transition."""

    record_type = record.get("recordType")
    if record_type not in {"authChallengeV2", "authMfaEnrollmentV2"}:
        raise AuthV2Unavailable()
    required = [
        "recordType",
        "stateIdHash",
        "csrfHash",
        "scope",
        "accountHash",
        "username",
        "cognitoSession",
        "createdAt",
        "expiresAt",
    ]
    if record_type == "authChallengeV2":
        required.append("challengeName")
    if (
        record.get("scope") != _SCOPE
        or not all(_hex_hash(record.get(key)) for key in ("stateIdHash", "csrfHash", "accountHash"))
        or not all(
            isinstance(record.get(key), str) and bool(record.get(key))
            for key in ("username", "cognitoSession")
        )
        or type(record.get("createdAt")) is not int
        or type(record.get("expiresAt")) is not int
        or int(record["createdAt"]) < 0
        or int(record["expiresAt"]) <= int(record["createdAt"])
        or (
            record_type == "authChallengeV2"
            and record.get("challengeName") not in _ALLOWED_CHALLENGES
        )
    ):
        raise AuthV2Unavailable()
    canonical = {key: record[key] for key in required}
    return _sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    )


def _valid_ephemeral_record(
    value: Any,
    *,
    expected_type: str,
    expected_binding_hash: Optional[str] = None,
    now: int,
) -> bool:
    if not isinstance(value, Mapping):
        return False
    try:
        binding_hash = _ephemeral_state_binding_hash(value)
        return (
            value.get("recordType") == expected_type
            and _hex_hash(value.get("stateBindingHash"))
            and hmac.compare_digest(str(value["stateBindingHash"]), binding_hash)
            and (
                expected_binding_hash is None
                or hmac.compare_digest(str(value["stateBindingHash"]), expected_binding_hash)
            )
            and value.get("scope") == _SCOPE
            and value.get("consumedAt") is None
            and type(value.get("expiresAt")) is int
            and int(value["expiresAt"])
            <= int(value["createdAt"]) + STATE_SECONDS
            and int(value["expiresAt"]) > now
        )
    except (AuthV2Unavailable, KeyError, TypeError, ValueError):
        return False


def _failure_events(
    current: Optional[Mapping[str, Any]], *, now: int, window_seconds: int
) -> list[dict[str, Any]]:
    """Return the validated events still inside the exact rolling window."""

    if current is None:
        return []
    if (
        current.get("recordType") != "authFailureWindowV2"
        or type(now) is not int
        or type(window_seconds) is not int
        or now < 0
        or window_seconds < 1
    ):
        raise AuthV2Unavailable()
    raw_events = current.get("events")
    if not isinstance(raw_events, list) or len(raw_events) > 64:
        raise AuthV2Unavailable()
    unique_ids: set[str] = set()
    validated: list[dict[str, Any]] = []
    for raw_event in raw_events:
        if not isinstance(raw_event, Mapping) or set(raw_event) != {
            "eventIdHash",
            "occurredAt",
        }:
            raise AuthV2Unavailable()
        event_id_hash = raw_event.get("eventIdHash")
        occurred_at = raw_event.get("occurredAt")
        if (
            not isinstance(event_id_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", event_id_hash) is None
            or event_id_hash in unique_ids
            or type(occurred_at) is not int
            or occurred_at < 0
            or occurred_at > now
        ):
            raise AuthV2Unavailable()
        unique_ids.add(event_id_hash)
        if occurred_at > now - window_seconds:
            validated.append(
                {"eventIdHash": event_id_hash, "occurredAt": occurred_at}
            )
    return sorted(validated, key=lambda item: (item["occurredAt"], item["eventIdHash"]))


class DynamoAuthV2Store:
    """Isolated low-level DynamoDB store used only by Auth Admin v2.

    Session and ephemeral transitions are conditional.  Failure capacity for
    account and source-IP dimensions is reserved in one transaction before a
    provider call, so concurrent calls cannot exceed the configured limits.
    """

    def __init__(self, client: Any):
        self.client = client

    @staticmethod
    def _serialize(value: Any) -> dict[str, Any]:
        if isinstance(value, bool):
            return {"BOOL": value}
        if isinstance(value, str):
            return {"S": value}
        if type(value) is int:
            return {"N": str(value)}
        if isinstance(value, Mapping):
            if any(not isinstance(key, str) for key in value):
                raise AuthV2Unavailable()
            return {
                "M": {
                    key: DynamoAuthV2Store._serialize(item)
                    for key, item in value.items()
                    if item is not None
                }
            }
        if isinstance(value, (list, tuple)):
            return {"L": [DynamoAuthV2Store._serialize(item) for item in value]}
        raise AuthV2Unavailable()

    @staticmethod
    def _deserialize(value: Mapping[str, Any]) -> Any:
        if not isinstance(value, Mapping):
            raise AuthV2Unavailable()
        if set(value) == {"S"} and isinstance(value["S"], str):
            return value["S"]
        if set(value) == {"BOOL"} and type(value["BOOL"]) is bool:
            return value["BOOL"]
        if set(value) == {"N"} and isinstance(value["N"], str):
            if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value["N"]):
                return int(value["N"])
            raise AuthV2Unavailable()
        if set(value) == {"M"} and isinstance(value["M"], Mapping):
            if any(not isinstance(key, str) for key in value["M"]):
                raise AuthV2Unavailable()
            return {
                key: DynamoAuthV2Store._deserialize(item)
                for key, item in value["M"].items()
            }
        if set(value) == {"L"} and isinstance(value["L"], list):
            return [DynamoAuthV2Store._deserialize(item) for item in value["L"]]
        raise AuthV2Unavailable()

    @classmethod
    def _serialize_item(cls, item: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(item, Mapping) or any(
            not isinstance(key, str) for key in item
        ):
            raise AuthV2Unavailable()
        return {
            key: cls._serialize(value)
            for key, value in item.items()
            if value is not None
        }

    @classmethod
    def _deserialize_item(cls, item: Any) -> Optional[dict[str, Any]]:
        if not isinstance(item, Mapping) or not item:
            return None
        return {str(key): cls._deserialize(value) for key, value in item.items()}

    def put_session(self, item: Mapping[str, Any]) -> None:
        if not _valid_session_record(item, now=int(item.get("createdAt") or -1)):
            raise AuthV2Unavailable()
        try:
            self.client.put_item(
                TableName=SESSION_TABLE_NAME,
                Item=self._serialize_item(item),
                ConditionExpression="attribute_not_exists(#sessionIdHash)",
                ExpressionAttributeNames={"#sessionIdHash": "sessionIdHash"},
            )
        except AuthV2Unavailable:
            raise
        except Exception as exc:
            raise AuthV2Unavailable() from exc

    def get_session(
        self, session_id_hash: str, *, consistent_read: bool
    ) -> Optional[dict[str, Any]]:
        try:
            response = self.client.get_item(
                TableName=SESSION_TABLE_NAME,
                Key=self._serialize_item({"sessionIdHash": session_id_hash}),
                ConsistentRead=consistent_read,
            )
        except AuthV2Unavailable:
            raise
        except Exception as exc:
            raise AuthV2Unavailable() from exc
        return self._deserialize_item(response.get("Item"))

    def touch_session(
        self,
        session_id_hash: str,
        *,
        now: int,
        idle_expires_at: int,
        absolute_expires_at: int,
        subject: str,
        account_purpose: str,
        session_version: int,
    ) -> dict[str, Any]:
        if (
            not _hex_hash(session_id_hash)
            or type(now) is not int
            or type(idle_expires_at) is not int
            or type(absolute_expires_at) is not int
            or not isinstance(subject, str)
            or not subject
            or account_purpose not in {"qa", "client-owner"}
            or type(session_version) is not int
            or session_version < 1
            or not now < idle_expires_at <= absolute_expires_at
        ):
            raise AuthV2Unavailable()
        transaction = [
            {
                "Update": {
                    "TableName": SESSION_TABLE_NAME,
                    "Key": self._serialize_item({"sessionIdHash": session_id_hash}),
                    "ConditionExpression": (
                        "attribute_exists(#sessionIdHash) "
                        "AND #recordType = :recordType AND #scope = :scope "
                        "AND attribute_not_exists(#revokedAt) "
                        "AND #subject = :subject "
                        "AND #accountPurpose = :accountPurpose "
                        "AND #lastSeenAt <= :now AND #absoluteExpiresAt = :absolute "
                        "AND #absoluteExpiresAt > :now AND #idleExpiresAt > :now "
                        "AND #sessionVersion = :sessionVersion"
                    ),
                    "UpdateExpression": (
                        "SET #lastSeenAt = :now, #idleExpiresAt = :idleExpiresAt"
                    ),
                    "ExpressionAttributeNames": {
                        "#sessionIdHash": "sessionIdHash",
                        "#recordType": "recordType",
                        "#scope": "scope",
                        "#revokedAt": "revokedAt",
                        "#subject": "subject",
                        "#accountPurpose": "accountPurpose",
                        "#absoluteExpiresAt": "absoluteExpiresAt",
                        "#idleExpiresAt": "idleExpiresAt",
                        "#lastSeenAt": "lastSeenAt",
                        "#sessionVersion": "sessionVersion",
                    },
                    "ExpressionAttributeValues": self._serialize_item(
                        {
                            ":recordType": "authSessionV2",
                            ":scope": _SCOPE,
                            ":subject": subject,
                            ":accountPurpose": account_purpose,
                            ":absolute": absolute_expires_at,
                            ":now": now,
                            ":idleExpiresAt": idle_expires_at,
                            ":sessionVersion": session_version,
                        }
                    ),
                }
            },
            {
                "ConditionCheck": {
                    "TableName": APPROVED_TABLE_NAME,
                    "Key": self._serialize_item(
                        {
                            "pk": APPROVED_PARTITION_KEY,
                            "sk": f"SUBJECT#{subject}",
                        }
                    ),
                    "ConditionExpression": (
                        "#contractVersion = :contractVersion AND #scope = :scope "
                        "AND #subject = :subject "
                        "AND #accountPurpose = :accountPurpose "
                        "AND #sessionVersion = :sessionVersion "
                        "AND #enabled = :enabled"
                    ),
                    "ExpressionAttributeNames": {
                        "#contractVersion": "contractVersion",
                        "#scope": "scope",
                        "#subject": "subject",
                        "#accountPurpose": "accountPurpose",
                        "#sessionVersion": "sessionVersion",
                        "#enabled": "enabled",
                    },
                    "ExpressionAttributeValues": self._serialize_item(
                        {
                            ":contractVersion": 1,
                            ":scope": _SCOPE,
                            ":subject": subject,
                            ":accountPurpose": account_purpose,
                            ":sessionVersion": session_version,
                            ":enabled": True,
                        }
                    ),
                }
            },
        ]
        request_token = hashlib.sha256(
            json.dumps(
                {
                    "sessionIdHash": session_id_hash,
                    "subject": subject,
                    "accountPurpose": account_purpose,
                    "sessionVersion": session_version,
                    "now": now,
                    "idleExpiresAt": idle_expires_at,
                    "absoluteExpiresAt": absolute_expires_at,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:32]
        try:
            self.client.transact_write_items(
                TransactItems=transaction,
                ClientRequestToken=request_token,
            )
        except AuthV2Unavailable:
            raise
        except Exception as exc:
            if _conditional_check_failed(exc) or _transaction_canceled_by_condition_only(
                exc, expected_item_count=len(transaction)
            ):
                raise CurrentUserSessionStale("current user state changed") from exc
            raise AuthV2Unavailable() from exc
        item = self.get_session(session_id_hash, consistent_read=True)
        if (
            not _valid_session_record(item, now=now)
            or item.get("subject") != subject
            or item.get("accountPurpose") != account_purpose
            or item.get("sessionVersion") != session_version
        ):
            raise CurrentUserSessionStale("session changed after touch")
        return item

    def rotate_session(
        self, old_session_id_hash: str, new_item: Mapping[str, Any], *, now: int
    ) -> None:
        if (
            not _hex_hash(old_session_id_hash)
            or not _valid_session_record(new_item, now=now)
            or old_session_id_hash == new_item.get("sessionIdHash")
        ):
            raise AuthV2Unavailable()
        owner_condition = ""
        owner_names: dict[str, str] = {}
        owner_values: dict[str, Any] = {}
        if new_item.get("accountPurpose") == "client-owner":
            owner_condition = " AND #cognitoUsername = :cognitoUsername"
            owner_names["#cognitoUsername"] = "cognitoUsername"
            owner_values[":cognitoUsername"] = new_item["cognitoUsername"]
        try:
            self.client.transact_write_items(
                TransactItems=[
                    {
                        "Update": {
                            "TableName": SESSION_TABLE_NAME,
                            "Key": self._serialize_item(
                                {"sessionIdHash": old_session_id_hash}
                            ),
                            "ConditionExpression": (
                                "attribute_exists(#sessionIdHash) "
                                "AND attribute_not_exists(#revokedAt) "
                                "AND #recordType = :recordType AND #scope = :scope "
                                "AND #subject = :subject AND #accountHash = :accountHash "
                                "AND #accountPurpose = :accountPurpose "
                                "AND #sessionVersion = :sessionVersion "
                                "AND #createdAt = :createdAt "
                                "AND #absoluteExpiresAt = :absoluteExpiresAt "
                                "AND #csrfHash <> :csrfHash "
                                "AND #idleExpiresAt > :now AND #absoluteExpiresAt > :now"
                                + owner_condition
                            ),
                            "UpdateExpression": "SET #revokedAt = :now",
                            "ExpressionAttributeNames": {
                                "#sessionIdHash": "sessionIdHash",
                                "#revokedAt": "revokedAt",
                                "#recordType": "recordType",
                                "#scope": "scope",
                                "#subject": "subject",
                                "#accountHash": "accountHash",
                                "#accountPurpose": "accountPurpose",
                                "#sessionVersion": "sessionVersion",
                                "#createdAt": "createdAt",
                                "#csrfHash": "csrfHash",
                                "#idleExpiresAt": "idleExpiresAt",
                                "#absoluteExpiresAt": "absoluteExpiresAt",
                                **owner_names,
                            },
                            "ExpressionAttributeValues": self._serialize_item(
                                {
                                    ":now": now,
                                    ":recordType": "authSessionV2",
                                    ":scope": _SCOPE,
                                    ":subject": new_item["subject"],
                                    ":accountHash": new_item["accountHash"],
                                    ":accountPurpose": new_item["accountPurpose"],
                                    ":sessionVersion": int(new_item["sessionVersion"]),
                                    ":createdAt": int(new_item["createdAt"]),
                                    ":absoluteExpiresAt": int(
                                        new_item["absoluteExpiresAt"]
                                    ),
                                    ":csrfHash": str(new_item["csrfHash"]),
                                    **owner_values,
                                }
                            ),
                        }
                    },
                    {
                        "Put": {
                            "TableName": SESSION_TABLE_NAME,
                            "Item": self._serialize_item(new_item),
                            "ConditionExpression": "attribute_not_exists(#sessionIdHash)",
                            "ExpressionAttributeNames": {
                                "#sessionIdHash": "sessionIdHash"
                            },
                        }
                    },
                    {
                        "ConditionCheck": {
                            "TableName": APPROVED_TABLE_NAME,
                            "Key": self._serialize_item(
                                {
                                    "pk": APPROVED_PARTITION_KEY,
                                    "sk": f"SUBJECT#{new_item['subject']}",
                                }
                            ),
                            "ConditionExpression": (
                                "#contractVersion = :contractVersion "
                                "AND #scope = :scope AND #subject = :subject "
                                "AND #accountPurpose = :accountPurpose "
                                "AND #sessionVersion = :sessionVersion "
                                "AND #enabled = :enabled"
                            ),
                            "ExpressionAttributeNames": {
                                "#contractVersion": "contractVersion",
                                "#scope": "scope",
                                "#subject": "subject",
                                "#accountPurpose": "accountPurpose",
                                "#sessionVersion": "sessionVersion",
                                "#enabled": "enabled",
                            },
                            "ExpressionAttributeValues": self._serialize_item(
                                {
                                    ":contractVersion": 1,
                                    ":scope": _SCOPE,
                                    ":subject": new_item["subject"],
                                    ":accountPurpose": new_item["accountPurpose"],
                                    ":sessionVersion": int(
                                        new_item["sessionVersion"]
                                    ),
                                    ":enabled": True,
                                }
                            ),
                        }
                    },
                ]
            )
        except AuthV2Unavailable:
            raise
        except Exception as exc:
            raise AuthV2Unavailable() from exc

    def revoke_session(self, session_id_hash: str, *, now: int) -> bool:
        if not _hex_hash(session_id_hash) or type(now) is not int or now < 0:
            raise AuthV2Unavailable()
        try:
            self.client.update_item(
                TableName=SESSION_TABLE_NAME,
                Key=self._serialize_item({"sessionIdHash": session_id_hash}),
                ConditionExpression=(
                    "attribute_exists(#sessionIdHash) "
                    "AND #recordType = :recordType AND #scope = :scope "
                    "AND attribute_not_exists(#revokedAt)"
                ),
                UpdateExpression="SET #revokedAt = :now",
                ExpressionAttributeNames={
                    "#sessionIdHash": "sessionIdHash",
                    "#recordType": "recordType",
                    "#scope": "scope",
                    "#revokedAt": "revokedAt",
                },
                ExpressionAttributeValues=self._serialize_item(
                    {":now": now, ":recordType": "authSessionV2", ":scope": _SCOPE}
                ),
            )
            return True
        except Exception as exc:
            if _conditional_check_failed(exc):
                return False
            raise AuthV2Unavailable() from exc

    def put_ephemeral(self, item: Mapping[str, Any]) -> None:
        record_type = item.get("recordType") if isinstance(item, Mapping) else None
        created_at = item.get("createdAt") if isinstance(item, Mapping) else None
        if (
            record_type not in {"authChallengeV2", "authMfaEnrollmentV2"}
            or type(created_at) is not int
            or not _valid_ephemeral_record(
                item, expected_type=str(record_type), now=int(created_at)
            )
            or item.get("claimedAt") is not None
            or item.get("consumedAt") is not None
        ):
            raise AuthV2Unavailable()
        try:
            self.client.put_item(
                TableName=CHALLENGE_TABLE_NAME,
                Item=self._serialize_item(item),
                ConditionExpression="attribute_not_exists(#stateIdHash)",
                ExpressionAttributeNames={"#stateIdHash": "stateIdHash"},
            )
        except AuthV2Unavailable:
            raise
        except Exception as exc:
            raise AuthV2Unavailable() from exc

    def get_ephemeral(
        self, state_id_hash: str, *, consistent_read: bool
    ) -> Optional[dict[str, Any]]:
        try:
            response = self.client.get_item(
                TableName=CHALLENGE_TABLE_NAME,
                Key=self._serialize_item({"stateIdHash": state_id_hash}),
                ConsistentRead=consistent_read,
            )
        except AuthV2Unavailable:
            raise
        except Exception as exc:
            raise AuthV2Unavailable() from exc
        return self._deserialize_item(response.get("Item"))

    def claim_ephemeral(
        self,
        state_id_hash: str,
        *,
        expected_type: str,
        expected_binding_hash: str,
        now: int,
    ) -> Optional[dict[str, Any]]:
        if (
            not _hex_hash(state_id_hash)
            or expected_type not in {"authChallengeV2", "authMfaEnrollmentV2"}
            or not _hex_hash(expected_binding_hash)
            or type(now) is not int
            or now < 0
        ):
            raise AuthV2Unavailable()
        claim_token = secrets.token_urlsafe(32)
        claim_token_hash = _sha256(claim_token)
        try:
            response = self.client.update_item(
                TableName=CHALLENGE_TABLE_NAME,
                Key=self._serialize_item({"stateIdHash": state_id_hash}),
                ConditionExpression=(
                    "#recordType = :recordType AND #scope = :scope "
                    "AND #stateBindingHash = :stateBindingHash "
                    "AND #expiresAt > :now "
                    "AND attribute_not_exists(#claimedAt) "
                    "AND attribute_not_exists(#consumedAt)"
                ),
                UpdateExpression=(
                    "SET #claimedAt = :now, #claimTokenHash = :claimTokenHash"
                ),
                ExpressionAttributeNames={
                    "#recordType": "recordType",
                    "#scope": "scope",
                    "#stateBindingHash": "stateBindingHash",
                    "#expiresAt": "expiresAt",
                    "#claimedAt": "claimedAt",
                    "#claimTokenHash": "claimTokenHash",
                    "#consumedAt": "consumedAt",
                },
                ExpressionAttributeValues=self._serialize_item(
                    {
                        ":recordType": expected_type,
                        ":scope": _SCOPE,
                        ":stateBindingHash": expected_binding_hash,
                        ":now": now,
                        ":claimTokenHash": claim_token_hash,
                    }
                ),
                ReturnValues="ALL_NEW",
            )
        except Exception as exc:
            if _conditional_check_failed(exc):
                return None
            raise AuthV2Unavailable() from exc
        try:
            claimed = self._deserialize_item(response.get("Attributes"))
            if claimed is None:
                raise AuthV2Unavailable()
        except Exception as exc:
            try:
                self.release_ephemeral_claim(
                    state_id_hash,
                    now=now,
                    claim_token=claim_token,
                    expected_binding_hash=expected_binding_hash,
                )
            except Exception:
                _safe_log(
                    "warning",
                    "Unable to release a malformed DynamoDB claim response.",
                    code="auth_v2_malformed_claim_release_failed",
                )
            raise AuthV2Unavailable() from exc
        claimed["claimToken"] = claim_token
        return claimed

    def release_ephemeral_claim(
        self,
        state_id_hash: str,
        *,
        now: int,
        claim_token: str,
        expected_binding_hash: str,
    ) -> bool:
        if (
            not _hex_hash(state_id_hash)
            or not isinstance(claim_token, str)
            or not claim_token
            or not _hex_hash(expected_binding_hash)
            or type(now) is not int
            or now < 0
        ):
            raise AuthV2Unavailable()
        try:
            self.client.update_item(
                TableName=CHALLENGE_TABLE_NAME,
                Key=self._serialize_item({"stateIdHash": state_id_hash}),
                ConditionExpression=(
                    "#scope = :scope AND #stateBindingHash = :stateBindingHash "
                    "AND #claimTokenHash = :claimTokenHash AND #expiresAt > :now "
                    "AND attribute_not_exists(#consumedAt)"
                ),
                UpdateExpression="REMOVE #claimedAt, #claimTokenHash",
                ExpressionAttributeNames={
                    "#claimedAt": "claimedAt",
                    "#claimTokenHash": "claimTokenHash",
                    "#scope": "scope",
                    "#stateBindingHash": "stateBindingHash",
                    "#expiresAt": "expiresAt",
                    "#consumedAt": "consumedAt",
                },
                ExpressionAttributeValues=self._serialize_item(
                    {
                        ":now": now,
                        ":scope": _SCOPE,
                        ":stateBindingHash": expected_binding_hash,
                        ":claimTokenHash": _sha256(claim_token),
                    }
                ),
            )
            return True
        except Exception as exc:
            if _conditional_check_failed(exc):
                return False
            raise AuthV2Unavailable() from exc

    def consume_ephemeral_claim(
        self,
        state_id_hash: str,
        *,
        now: int,
        claim_token: str,
        expected_binding_hash: str,
    ) -> bool:
        if (
            not _hex_hash(state_id_hash)
            or not isinstance(claim_token, str)
            or not claim_token
            or not _hex_hash(expected_binding_hash)
            or type(now) is not int
            or now < 0
        ):
            raise AuthV2Unavailable()
        try:
            self.client.update_item(
                TableName=CHALLENGE_TABLE_NAME,
                Key=self._serialize_item({"stateIdHash": state_id_hash}),
                ConditionExpression=(
                    "#scope = :scope AND #stateBindingHash = :stateBindingHash "
                    "AND #claimTokenHash = :claimTokenHash AND #expiresAt > :now "
                    "AND attribute_not_exists(#consumedAt)"
                ),
                UpdateExpression=(
                    "SET #consumedAt = :now "
                    "REMOVE #claimedAt, #claimTokenHash, #cognitoSession, #username"
                ),
                ExpressionAttributeNames={
                    "#claimedAt": "claimedAt",
                    "#claimTokenHash": "claimTokenHash",
                    "#scope": "scope",
                    "#stateBindingHash": "stateBindingHash",
                    "#expiresAt": "expiresAt",
                    "#consumedAt": "consumedAt",
                    "#cognitoSession": "cognitoSession",
                    "#username": "username",
                },
                ExpressionAttributeValues=self._serialize_item(
                    {
                        ":now": now,
                        ":scope": _SCOPE,
                        ":stateBindingHash": expected_binding_hash,
                        ":claimTokenHash": _sha256(claim_token),
                    }
                ),
            )
            return True
        except Exception as exc:
            if _conditional_check_failed(exc):
                return False
            raise AuthV2Unavailable() from exc

    def transition_ephemeral_claim(
        self,
        state_id_hash: str,
        *,
        expected_type: str,
        expected_binding_hash: str,
        expected_account_hash: str,
        claim_token: str,
        now: int,
        next_item: Mapping[str, Any],
    ) -> bool:
        if (
            not _hex_hash(state_id_hash)
            or expected_type not in {"authChallengeV2", "authMfaEnrollmentV2"}
            or not _hex_hash(expected_binding_hash)
            or not _hex_hash(expected_account_hash)
            or not isinstance(claim_token, str)
            or not claim_token
            or type(now) is not int
            or now < 0
            or not isinstance(next_item, Mapping)
            or next_item.get("accountHash") != expected_account_hash
        ):
            raise AuthV2Unavailable()

        next_type = next_item.get("recordType")
        if next_type == "authSessionV2":
            if not _valid_session_record(next_item, now=now):
                raise AuthV2Unavailable()
            target_table = SESSION_TABLE_NAME
            target_key = "sessionIdHash"
        elif next_type in {"authChallengeV2", "authMfaEnrollmentV2"}:
            if (
                next_item.get("stateIdHash") == state_id_hash
                or not _valid_ephemeral_record(
                    next_item, expected_type=str(next_type), now=now
                )
                or next_item.get("claimedAt") is not None
                or next_item.get("consumedAt") is not None
            ):
                raise AuthV2Unavailable()
            target_table = CHALLENGE_TABLE_NAME
            target_key = "stateIdHash"
        else:
            raise AuthV2Unavailable()

        claim_token_hash = _sha256(claim_token)
        transaction: list[dict[str, Any]] = [
            {
                "Update": {
                    "TableName": CHALLENGE_TABLE_NAME,
                    "Key": self._serialize_item({"stateIdHash": state_id_hash}),
                    "ConditionExpression": (
                        "attribute_exists(#stateIdHash) "
                        "AND #recordType = :recordType AND #scope = :scope "
                        "AND #accountHash = :accountHash "
                        "AND #stateBindingHash = :stateBindingHash "
                        "AND #claimTokenHash = :claimTokenHash "
                        "AND #expiresAt > :now AND attribute_exists(#claimedAt) "
                        "AND attribute_not_exists(#consumedAt)"
                    ),
                    "UpdateExpression": (
                        "SET #consumedAt = :now "
                        "REMOVE #claimedAt, #claimTokenHash, #cognitoSession, #username"
                    ),
                    "ExpressionAttributeNames": {
                        "#stateIdHash": "stateIdHash",
                        "#recordType": "recordType",
                        "#scope": "scope",
                        "#accountHash": "accountHash",
                        "#stateBindingHash": "stateBindingHash",
                        "#claimTokenHash": "claimTokenHash",
                        "#expiresAt": "expiresAt",
                        "#claimedAt": "claimedAt",
                        "#consumedAt": "consumedAt",
                        "#cognitoSession": "cognitoSession",
                        "#username": "username",
                    },
                    "ExpressionAttributeValues": self._serialize_item(
                        {
                            ":recordType": expected_type,
                            ":scope": _SCOPE,
                            ":accountHash": expected_account_hash,
                            ":stateBindingHash": expected_binding_hash,
                            ":claimTokenHash": claim_token_hash,
                            ":now": now,
                        }
                    ),
                }
            },
            {
                "Put": {
                    "TableName": target_table,
                    "Item": self._serialize_item(next_item),
                    "ConditionExpression": f"attribute_not_exists(#{target_key})",
                    "ExpressionAttributeNames": {f"#{target_key}": target_key},
                }
            },
        ]
        if next_type == "authSessionV2":
            transaction.append(
                {
                    "ConditionCheck": {
                        "TableName": APPROVED_TABLE_NAME,
                        "Key": self._serialize_item(
                            {
                                "pk": APPROVED_PARTITION_KEY,
                                "sk": f"SUBJECT#{next_item['subject']}",
                            }
                        ),
                        "ConditionExpression": (
                            "#contractVersion = :contractVersion AND #scope = :scope "
                            "AND #subject = :subject "
                            "AND #accountPurpose = :accountPurpose "
                            "AND #sessionVersion = :sessionVersion "
                            "AND #enabled = :enabled"
                        ),
                        "ExpressionAttributeNames": {
                            "#contractVersion": "contractVersion",
                            "#scope": "scope",
                            "#subject": "subject",
                            "#accountPurpose": "accountPurpose",
                            "#sessionVersion": "sessionVersion",
                            "#enabled": "enabled",
                        },
                        "ExpressionAttributeValues": self._serialize_item(
                            {
                                ":contractVersion": 1,
                                ":scope": _SCOPE,
                                ":subject": next_item["subject"],
                                ":accountPurpose": next_item["accountPurpose"],
                                ":sessionVersion": next_item["sessionVersion"],
                                ":enabled": True,
                            }
                        ),
                    }
                }
            )
        intent = {
            "stateIdHash": state_id_hash,
            "expectedType": expected_type,
            "expectedBindingHash": expected_binding_hash,
            "claimTokenHash": claim_token_hash,
            "now": now,
            "nextItem": dict(next_item),
        }
        request_token = hashlib.sha256(
            json.dumps(intent, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:32]
        try:
            self.client.transact_write_items(
                TransactItems=transaction, ClientRequestToken=request_token
            )
            return True
        except Exception as exc:
            if _conditional_check_failed(exc) or _transaction_canceled_by_condition_only(
                exc, expected_item_count=len(transaction)
            ):
                return False
            raise AuthV2Unavailable() from exc

    def reserve_failure_attempt(
        self,
        operation: str,
        account_hash: str,
        ip_hash: str,
        *,
        now: int,
        window_seconds: int,
        account_limit: int,
        ip_limit: int,
    ) -> dict[str, Any]:
        dimensions = (
            ("account", account_hash, account_limit),
            ("ip", ip_hash, ip_limit),
        )
        reservation_id = secrets.token_hex(16)
        event_id_hash = _sha256(reservation_id)
        for _ in range(4):
            writes: list[dict[str, Any]] = []
            reservation_keys: list[str] = []
            for dimension, key_hash, limit in dimensions:
                key = {"failureKey": f"{operation}#{dimension}#{key_hash}"}
                try:
                    response = self.client.get_item(
                        TableName=THROTTLE_TABLE_NAME,
                        Key=self._serialize_item(key),
                        ConsistentRead=True,
                    )
                except AuthV2Unavailable:
                    raise
                except Exception as exc:
                    raise AuthV2Unavailable() from exc
                current = self._deserialize_item(response.get("Item"))
                prior_version = int(current.get("version") or 0) if current else 0
                events = _failure_events(current, now=now, window_seconds=window_seconds)
                if len(events) >= limit:
                    raise AuthV2Throttled()
                events.append({"eventIdHash": event_id_hash, "occurredAt": now})
                next_item = {
                    **key,
                    "recordType": "authFailureWindowV2",
                    "operation": operation,
                    "dimension": dimension,
                    "keyHash": key_hash,
                    "events": events,
                    "failureCount": len(events),
                    "windowStartedAt": min(event["occurredAt"] for event in events),
                    "windowExpiresAt": max(event["occurredAt"] for event in events)
                    + window_seconds,
                    "expiresAt": max(event["occurredAt"] for event in events)
                    + window_seconds,
                    "version": prior_version + 1,
                }
                condition = (
                    "attribute_not_exists(#failureKey)"
                    if current is None
                    else "#version = :expectedVersion"
                )
                attribute_names = (
                    {"#failureKey": "failureKey"}
                    if current is None
                    else {"#version": "version"}
                )
                put: dict[str, Any] = {
                    "TableName": THROTTLE_TABLE_NAME,
                    "Item": self._serialize_item(next_item),
                    "ConditionExpression": condition,
                    "ExpressionAttributeNames": attribute_names,
                }
                if current is not None:
                    put["ExpressionAttributeValues"] = self._serialize_item(
                        {":expectedVersion": prior_version}
                    )
                writes.append({"Put": put})
                reservation_keys.append(str(key["failureKey"]))
            try:
                self.client.transact_write_items(
                    TransactItems=writes,
                    ClientRequestToken=secrets.token_hex(16),
                )
                return {
                    "mode": "reserved",
                    "failureKeys": reservation_keys,
                    "reservationId": reservation_id,
                    "windowSeconds": window_seconds,
                }
            except Exception as exc:
                if _aws_error_code(exc) == "TransactionCanceledException":
                    continue
                raise AuthV2Unavailable() from exc
        raise AuthV2Unavailable()

    def release_failure_attempt(self, reservation: Mapping[str, Any], *, now: int) -> None:
        failure_keys = reservation.get("failureKeys")
        reservation_id = reservation.get("reservationId")
        window_seconds = reservation.get("windowSeconds")
        if (
            not isinstance(failure_keys, list)
            or len(failure_keys) != 2
            or len(set(failure_keys)) != 2
            or not all(isinstance(key, str) and key for key in failure_keys)
            or not isinstance(reservation_id, str)
            or len(reservation_id) != 32
            or type(window_seconds) is not int
            or not 1 <= int(window_seconds) <= 3_600
        ):
            raise AuthV2Unavailable()
        event_id_hash = _sha256(reservation_id)
        for _ in range(4):
            snapshots: list[Optional[Mapping[str, Any]]] = []
            found: list[Optional[bool]] = []
            for failure_key in failure_keys:
                try:
                    response = self.client.get_item(
                        TableName=THROTTLE_TABLE_NAME,
                        Key=self._serialize_item({"failureKey": failure_key}),
                        ConsistentRead=True,
                    )
                except AuthV2Unavailable:
                    raise
                except Exception as exc:
                    raise AuthV2Unavailable() from exc
                current = self._deserialize_item(response.get("Item"))
                snapshots.append(current)
                if current is None:
                    found.append(None)
                    continue
                if not isinstance(current, Mapping):
                    raise AuthV2Unavailable()
                prior_version = int(current.get("version") or 0)
                all_events = current.get("events")
                if not isinstance(all_events, list):
                    raise AuthV2Unavailable()
                contained = any(
                    isinstance(event, Mapping)
                    and event.get("eventIdHash") == event_id_hash
                    for event in all_events
                )
                found.append(contained)
            if found == [None, None]:
                return
            if None in found:
                raise AuthV2Unavailable()
            if found == [False, False]:
                return
            if found != [True, True]:
                raise AuthV2Unavailable()

            writes: list[dict[str, Any]] = []
            for current in snapshots:
                if not isinstance(current, Mapping):
                    raise AuthV2Unavailable()
                prior_version = int(current.get("version") or 0)
                events = [
                    dict(event)
                    for event in _failure_events(
                        current, now=now, window_seconds=int(window_seconds)
                    )
                    if event["eventIdHash"] != event_id_hash
                ]
                next_item = dict(current)
                next_item.update(
                    {
                        "events": events,
                        "failureCount": len(events),
                        "windowStartedAt": min(
                            (event["occurredAt"] for event in events), default=now
                        ),
                        "windowExpiresAt": max(
                            (event["occurredAt"] for event in events), default=now
                        )
                        + (int(window_seconds) if events else 0),
                        "expiresAt": max(
                            (event["occurredAt"] for event in events), default=now
                        )
                        + (int(window_seconds) if events else 0),
                        "version": prior_version + 1,
                    }
                )
                writes.append(
                    {
                        "Put": {
                            "TableName": THROTTLE_TABLE_NAME,
                            "Item": self._serialize_item(next_item),
                            "ConditionExpression": "#version = :expectedVersion",
                            "ExpressionAttributeNames": {"#version": "version"},
                            "ExpressionAttributeValues": self._serialize_item(
                                {":expectedVersion": prior_version}
                            ),
                        }
                    }
                )
            try:
                self.client.transact_write_items(
                    TransactItems=writes,
                    ClientRequestToken=secrets.token_hex(16),
                )
                return
            except Exception as exc:
                if _aws_error_code(exc) == "TransactionCanceledException":
                    continue
                raise AuthV2Unavailable() from exc
        raise AuthV2Unavailable()


__all__ = [
    "ADMIN_HOST",
    "ADMIN_ORIGIN",
    "CHALLENGE_COOKIE_NAME",
    "COOKIE_NAMESPACE",
    "CSRF_COOKIE_NAME",
    "FAILURE_WINDOW_SECONDS",
    "MFA_ENROLLMENT_COOKIE_NAME",
    "SESSION_ABSOLUTE_SECONDS",
    "SESSION_COOKIE_NAME",
    "SESSION_IDLE_SECONDS",
    "STATE_SECONDS",
    "lambda_handler",
]
