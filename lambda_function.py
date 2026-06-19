import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from typing import Any, Optional
from urllib.parse import quote


SESSION_COOKIE_NAME = "__Host-zlp_session"
CHALLENGE_COOKIE_NAME = "__Host-zlp_challenge"
MFA_ENROLLMENT_COOKIE_NAME = "__Host-zlp_mfa_enroll"
CSRF_COOKIE_NAME = "zlp_csrf"
CHALLENGE_CSRF_COOKIE_NAME = "zlp_challenge_csrf"
MFA_ENROLLMENT_CSRF_COOKIE_NAME = "zlp_mfa_enroll_csrf"
CONTEXT_DOMAIN_HEADER = "x-zlp-domain"
CONTEXT_AUTH_PROFILE_HEADER = "x-zlp-auth-profile-id"
CONFIG_ENV_BASE64 = "AUTH_ADMIN_CONFIG_JSON_BASE64"
CONFIG_ENV_JSON = "AUTH_ADMIN_CONFIG_JSON"
ENVIRONMENT_ENV = "AUTH_ADMIN_ENVIRONMENT"
SESSION_TABLE_ENV = "AUTH_ADMIN_SESSION_TABLE_NAME"
USER_STATE_TABLE_ENV = "AUTH_ADMIN_USER_STATE_TABLE_NAME"
AUDIT_TABLE_ENV = "AUTH_ADMIN_AUDIT_TABLE_NAME"
DEFAULT_SESSION_SECONDS = 12 * 60 * 60
DEFAULT_CHALLENGE_SECONDS = 5 * 60
DEFAULT_MFA_ENROLLMENT_SECONDS = 5 * 60
AUTH_ENVIRONMENTS = {"dev", "test", "prod"}
ENVIRONMENT_CLAIM_MODES = {"single", "list"}
APPROVAL_STATUSES = {"pending", "approved", "rejected", "suspended"}
SUPPORTED_CHALLENGES = {"SOFTWARE_TOKEN_MFA", "MFA_SETUP"}
SECRET_KEY_FRAGMENTS = (
    "secret",
    "token",
    "password",
    "credential",
    "privatekey",
    "private_key",
    "apikey",
    "api_key",
)
SECRET_VALUE_MARKERS = (
    "-----BEGIN ",
    "AKIA",
    "ASIA",
    "xoxb-",
    "ghp_",
    "gho_",
)
CONTROL_OR_WHITESPACE_RE = re.compile(r"[\s\x00-\x1f\x7f]")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
TOTP_TEMPLATE_RE = re.compile(r"\{([A-Za-z][A-Za-z0-9_]*)\}")
TOTP_TEMPLATE_KEYS = {"issuer", "domain", "authProfileId", "tenantId", "username", "email"}
DOMAIN_RE = re.compile(r"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class AuthAdminError(Exception):
    status_code = 400
    public_message = "Invalid auth admin request"

    def __init__(self, message: Optional[str] = None, *, error_code: Optional[str] = None):
        super().__init__(message or self.public_message)
        if message:
            self.public_message = message
        self.error_code = _clean_string(error_code)


class AuthAdminConfigError(AuthAdminError):
    status_code = 500
    public_message = "Auth admin config is invalid"


class AuthAdminUnauthorized(AuthAdminError):
    status_code = 401
    public_message = "Authentication required"


class AuthAdminForbidden(AuthAdminError):
    status_code = 403
    public_message = "Admin access required"


class AuthAdminNotFound(AuthAdminError):
    status_code = 404
    public_message = "Not found"


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    if _method(event) == "OPTIONS":
        return _json_response(200, {"ok": True})

    try:
        path = _path(event)
        method = _method(event)

        if path == "/auth/session/signin" and method == "POST":
            return _signin_response(_request_payload(event))
        if path == "/auth/session/challenge/respond" and method == "POST":
            return _respond_challenge_response(event)
        if path == "/auth/session/mfa/setup" and method == "POST":
            return _mfa_setup_response(event)
        if path == "/auth/session/mfa/verify" and method == "POST":
            return _mfa_verify_response(event)
        if path == "/auth/session/mfa/enroll/start" and method == "POST":
            return _mfa_enroll_start_response(event)
        if path == "/auth/session/mfa/enroll/verify" and method == "POST":
            return _mfa_enroll_verify_response(event)
        if path == "/auth/session/mfa/disable" and method == "POST":
            return _mfa_disable_response(event)
        if path == "/auth/session/me" and method == "GET":
            session, profile = _require_session(event)
            return _json_response(200, {
                "ok": True,
                "account": _public_account_with_mfa(session, profile),
                "session": _public_session(session, profile),
            })
        if path == "/auth/session/logout" and method == "POST":
            return _logout_response(event)
        if path == "/auth/admin/users" and method == "GET":
            session, profile = _require_admin_session(event)
            users = _session_store(profile).list_users(_tenant_profile_key(profile))
            return _json_response(200, {
                "ok": True,
                "users": [_public_user(user, profile) for user in _sort_users(users)],
                "actor": _public_account(session, profile),
            })
        if method == "POST":
            target_subject, operation = _admin_user_operation(path)
            if operation == "approve":
                return _approve_user_response(event, target_subject)
            if operation == "groups":
                return _set_user_groups_response(event, target_subject)
            if operation == "suspend":
                return _set_user_enabled_response(event, target_subject, enabled=False)
            if operation == "reactivate":
                return _set_user_enabled_response(event, target_subject, enabled=True)
            if operation == "mfa/reset":
                return _reset_user_mfa_response(event, target_subject)
        return _json_response(404, {"ok": False, "error": "Auth admin route not found"})
    except AuthAdminError as exc:
        payload = {"ok": False, "error": exc.public_message}
        if exc.error_code:
            payload["errorCode"] = exc.error_code
        return _json_response(exc.status_code, payload)
    except ValueError as exc:
        return _json_response(400, {"ok": False, "error": str(exc)})
    except Exception as exc:
        _log("ERROR", "Unhandled auth admin error", errorType=type(exc).__name__)
        return _json_response(500, {"ok": False, "error": "Internal error"})


def load_config() -> dict[str, Any]:
    raw = _config_json()
    if not raw:
        raise AuthAdminConfigError(f"{CONFIG_ENV_BASE64} is required")
    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthAdminConfigError("Auth admin config must be valid JSON") from exc

    _reject_secret_like_config(config)
    if not isinstance(config, dict) or config.get("version") != 1:
        raise AuthAdminConfigError("Auth admin config version must be 1")
    profiles = config.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise AuthAdminConfigError("Auth admin config requires profiles")

    return {
        "version": 1,
        "profiles": [_validate_profile(profile, index) for index, profile in enumerate(profiles)],
    }


def _config_json() -> str:
    raw_base64 = str(os.getenv(CONFIG_ENV_BASE64, "") or "").strip()
    if raw_base64:
        try:
            return base64.b64decode(raw_base64, validate=True).decode("utf-8").strip()
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise AuthAdminConfigError(f"{CONFIG_ENV_BASE64} must be base64 UTF-8 JSON") from exc
    return str(os.getenv(CONFIG_ENV_JSON, "") or "").strip()


def _validate_profile(profile: Any, index: int) -> dict[str, Any]:
    if not isinstance(profile, dict):
        raise AuthAdminConfigError(f"Profile {index} must be an object")
    normalized = dict(profile)

    for key in ("domain", "authProfileId", "issuer", "userPoolId", "clientId", "tenantId"):
        if not _clean_string(normalized.get(key)):
            raise AuthAdminConfigError(f"Profile {index} requires {key}")
    if not DOMAIN_RE.fullmatch(str(normalized["domain"])):
        raise AuthAdminConfigError(f"Profile {index} domain is invalid")
    if not SAFE_ID_RE.fullmatch(str(normalized["authProfileId"])):
        raise AuthAdminConfigError(f"Profile {index} authProfileId is invalid")
    if not str(normalized["issuer"]).startswith("https://"):
        raise AuthAdminConfigError(f"Profile {index} issuer must be HTTPS")

    normalized["provider"] = _clean_string(normalized.get("provider") or "cognito")
    if normalized["provider"] != "cognito":
        raise AuthAdminConfigError(f"Profile {index} provider is not supported")

    normalized["environment"] = _environment_alias(normalized.get("environment") or _runtime_environment())
    normalized["audiences"] = _string_list(normalized.get("audiences")) or [_clean_string(normalized.get("clientId"))]
    normalized["allowedGroups"] = _string_list(normalized.get("allowedGroups"))
    normalized["adminGroups"] = _string_list(normalized.get("adminGroups"))
    normalized["manageableGroups"] = _string_list(normalized.get("manageableGroups")) or normalized["allowedGroups"]
    normalized["tenantClaim"] = _clean_string(normalized.get("tenantClaim") or "custom:tenant_id")
    normalized["environmentClaim"] = _clean_string(normalized.get("environmentClaim"))
    normalized["environmentClaimMode"] = _clean_string(normalized.get("environmentClaimMode") or "single")
    normalized["groupClaim"] = _clean_string(normalized.get("groupClaim") or "cognito:groups")
    normalized["defaultUserStatus"] = _clean_string(normalized.get("defaultUserStatus") or "pending")
    normalized["adminGroupsAutoApproved"] = normalized.get("adminGroupsAutoApproved", True) is True
    normalized["maxSessionSeconds"] = _positive_int(normalized.get("maxSessionSeconds"), DEFAULT_SESSION_SECONDS)
    normalized["enabled"] = normalized.get("enabled", True) is True

    if normalized["defaultUserStatus"] not in APPROVAL_STATUSES:
        raise AuthAdminConfigError(f"Profile {index} defaultUserStatus is invalid")
    if not normalized["allowedGroups"]:
        raise AuthAdminConfigError(f"Profile {index} requires allowedGroups")
    if not normalized["adminGroups"]:
        raise AuthAdminConfigError(f"Profile {index} requires adminGroups")
    if not set(normalized["adminGroups"]).issubset(set(normalized["allowedGroups"])):
        raise AuthAdminConfigError(f"Profile {index} adminGroups must be allowedGroups")
    if not set(normalized["manageableGroups"]).issubset(set(normalized["allowedGroups"])):
        raise AuthAdminConfigError(f"Profile {index} manageableGroups must be allowedGroups")
    if normalized["environmentClaim"] and not re.fullmatch(r"custom:[A-Za-z0-9_]{1,20}", normalized["environmentClaim"]):
        raise AuthAdminConfigError(f"Profile {index} environmentClaim is invalid")
    if normalized["environmentClaimMode"] not in ENVIRONMENT_CLAIM_MODES:
        raise AuthAdminConfigError(f"Profile {index} environmentClaimMode is invalid")
    if normalized["environmentClaimMode"] != "single" and not normalized["environmentClaim"]:
        raise AuthAdminConfigError(f"Profile {index} environmentClaimMode requires environmentClaim")

    custom_auth = normalized.get("customAuth")
    if not isinstance(custom_auth, dict) or not isinstance(custom_auth.get("signin"), dict) or custom_auth["signin"].get("enabled") is not True:
        raise AuthAdminConfigError(f"Profile {index} requires enabled customAuth.signin")

    return normalized


def _signin_response(payload: dict[str, Any]) -> dict[str, Any]:
    domain = _domain(payload.get("domain"))
    auth_profile_id = _safe_id(payload.get("authProfileId"))
    profile = _profile_for(domain, auth_profile_id)
    email = _email(payload.get("email"))
    password = _password(payload.get("password"))
    language = _language(payload.get("language"))

    try:
        response = _cognito_client().initiate_auth(
            ClientId=profile["clientId"],
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": email,
                "PASSWORD": password,
            },
            ClientMetadata=_client_metadata(domain, profile, language),
        )
    except Exception as exc:
        _log("WARNING", "Cognito signin failed", domain=domain, authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
        raise AuthAdminUnauthorized("Sign-in failed") from exc

    challenge = _clean_string(response.get("ChallengeName"))
    if challenge:
        return _create_challenge_response(domain, profile, response, username=email)

    auth_result = response.get("AuthenticationResult") if isinstance(response.get("AuthenticationResult"), dict) else {}
    return _create_private_session_response(domain, profile, auth_result, username=email)


def _create_private_session_response(
    domain: str,
    profile: dict[str, Any],
    auth_result: dict[str, Any],
    *,
    username: str,
    clear_challenge: bool = False,
) -> dict[str, Any]:
    id_token = _clean_string(auth_result.get("IdToken"))
    if not id_token:
        raise AuthAdminUnauthorized("Sign-in failed")
    claims = _verify_jwt(id_token, profile)
    claims_rejection = _claims_rejection_code(claims, profile)
    if claims_rejection:
        _log("WARNING", "JWT claims rejected", domain=domain, authProfileId=profile["authProfileId"], reason=claims_rejection)
        if claims_rejection == "environment_mismatch":
            raise AuthAdminForbidden(
                "Account does not belong to this environment",
                error_code="auth_environment_mismatch",
            )
        raise AuthAdminUnauthorized("Sign-in failed")

    store = _session_store(profile)
    now = _now_epoch()
    user_state = _upsert_user_state_from_claims(store, profile, claims, now)
    session_value = _random_urlsafe(32)
    csrf_value = _random_urlsafe(32)
    expires_at = min(int(claims.get("exp") or 0), now + int(profile["maxSessionSeconds"]))
    if expires_at <= now:
        raise AuthAdminUnauthorized("Sign-in failed")

    session = {
        "sessionIdHash": _sha256(session_value),
        "tenantProfileKey": _tenant_profile_key(profile),
        "domain": domain,
        "authProfileId": profile["authProfileId"],
        "environment": profile["environment"],
        "userPoolId": profile["userPoolId"],
        "clientId": profile["clientId"],
        "tenantId": profile["tenantId"],
        "subject": user_state["subject"],
        "username": user_state.get("username") or username,
        "email": user_state.get("email") or username,
        "emailHash": _sha256(user_state.get("email") or username),
        "roles": user_state.get("roles") or [],
        "approvalStatus": user_state.get("approvalStatus") or profile["defaultUserStatus"],
        "enabled": user_state.get("enabled", True) is True,
        "sessionVersion": int(user_state.get("sessionVersion") or 1),
        "csrfHash": _sha256(csrf_value),
        "createdAt": now,
        "lastSeenAt": now,
        "expiresAt": expires_at,
        "revokedAt": None,
    }
    store.put_session(session)

    max_age = max(0, expires_at - now)
    return _json_response(200, {
        "ok": True,
        "domain": domain,
        "authProfileId": profile["authProfileId"],
        "status": "signed-in",
        "session": _public_session(session, profile),
    }, cookies=[
        _cookie(SESSION_COOKIE_NAME, session_value, http_only=True, max_age=max_age),
        _cookie(_csrf_cookie_name(profile), csrf_value, http_only=False, max_age=max_age),
        *([
            _cookie(CHALLENGE_COOKIE_NAME, "", http_only=True, max_age=0),
            _cookie(_challenge_csrf_cookie_name(profile), "", http_only=False, max_age=0),
        ] if clear_challenge else []),
    ])


def _create_challenge_response(
    domain: str,
    profile: dict[str, Any],
    response: dict[str, Any],
    *,
    username: str,
) -> dict[str, Any]:
    challenge_name = _clean_string(response.get("ChallengeName"))
    if challenge_name not in SUPPORTED_CHALLENGES:
        raise AuthAdminUnauthorized("Sign-in requires an unsupported challenge")
    cognito_session = _clean_string(response.get("Session"))
    if not cognito_session:
        raise AuthAdminUnauthorized("Sign-in failed")
    challenge_parameters = response.get("ChallengeParameters") if isinstance(response.get("ChallengeParameters"), dict) else {}
    challenge_username = _clean_string(challenge_parameters.get("USER_ID_FOR_SRP") or challenge_parameters.get("USERNAME") or username)
    if not challenge_username:
        raise AuthAdminUnauthorized("Sign-in failed")

    challenge_value = _random_urlsafe(32)
    challenge_csrf_value = _random_urlsafe(32)
    now = _now_epoch()
    max_age = DEFAULT_CHALLENGE_SECONDS
    record = {
        "sessionIdHash": _sha256(challenge_value),
        "challengeCsrfHash": _sha256(challenge_csrf_value),
        "recordType": "authChallenge",
        "tenantProfileKey": _tenant_profile_key(profile),
        "domain": domain,
        "authProfileId": profile["authProfileId"],
        "environment": profile["environment"],
        "userPoolId": profile["userPoolId"],
        "clientId": profile["clientId"],
        "username": challenge_username,
        "emailHash": _sha256(username),
        "challengeName": challenge_name,
        "cognitoSession": cognito_session,
        "challengeParameters": _public_challenge_parameters(challenge_parameters),
        "createdAt": now,
        "expiresAt": now + max_age,
        "revokedAt": None,
    }
    _session_store(profile).put_session(record)
    return _json_response(200, {
        "ok": True,
        "domain": domain,
        "authProfileId": profile["authProfileId"],
        "status": "challenge-required",
        "challengeName": challenge_name,
        "challengeParameters": record["challengeParameters"],
    }, cookies=[
        _cookie(CHALLENGE_COOKIE_NAME, challenge_value, http_only=True, max_age=max_age),
        _cookie(_challenge_csrf_cookie_name(profile), challenge_csrf_value, http_only=False, max_age=max_age),
    ])


def _respond_challenge_response(event: dict[str, Any]) -> dict[str, Any]:
    payload = _request_payload(event)
    record, profile = _require_challenge(event, payload, expected_challenge="SOFTWARE_TOKEN_MFA")
    code = _totp_code(payload.get("code"))
    try:
        response = _cognito_client().respond_to_auth_challenge(
            ClientId=profile["clientId"],
            ChallengeName="SOFTWARE_TOKEN_MFA",
            Session=record["cognitoSession"],
            ChallengeResponses={
                "USERNAME": record["username"],
                "SOFTWARE_TOKEN_MFA_CODE": code,
            },
            ClientMetadata=_client_metadata(record["domain"], profile, ""),
        )
    except Exception as exc:
        _log("WARNING", "Cognito MFA challenge failed", domain=record["domain"], authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
        raise AuthAdminUnauthorized("Authentication challenge failed") from exc
    return _complete_challenge_response(record, profile, response)


def _mfa_setup_response(event: dict[str, Any]) -> dict[str, Any]:
    payload = _request_payload(event)
    record, profile = _require_challenge(event, payload, expected_challenge="MFA_SETUP")
    try:
        response = _cognito_client().associate_software_token(Session=record["cognitoSession"])
    except Exception as exc:
        _log("WARNING", "Cognito MFA setup failed", domain=record["domain"], authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
        raise AuthAdminUnauthorized("Authentication challenge failed") from exc
    secret_code = _clean_string(response.get("SecretCode"))
    next_session = _clean_string(response.get("Session"))
    if not secret_code or not next_session:
        raise AuthAdminUnauthorized("MFA setup failed")
    updated = dict(record)
    updated.update({
        "cognitoSession": next_session,
        "mfaSetupStartedAt": _now_epoch(),
    })
    _session_store(profile).put_session(updated)
    return _json_response(200, {
        "ok": True,
        "domain": record["domain"],
        "authProfileId": profile["authProfileId"],
        "status": "mfa-setup-ready",
        "setup": {
            "method": "software-token",
            "sharedSecret": secret_code,
            "otpauthUri": _totp_otpauth_uri(profile, record["username"], secret_code),
        },
    })


def _mfa_verify_response(event: dict[str, Any]) -> dict[str, Any]:
    payload = _request_payload(event)
    record, profile = _require_challenge(event, payload, expected_challenge="MFA_SETUP")
    code = _totp_code(payload.get("code"))
    try:
        response = _cognito_client().verify_software_token(
            Session=record["cognitoSession"],
            UserCode=code,
            FriendlyDeviceName=_totp_friendly_device_name(profile),
        )
    except Exception as exc:
        _log("WARNING", "Cognito MFA verification failed", domain=record["domain"], authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
        raise AuthAdminUnauthorized("Authentication challenge failed") from exc
    if _clean_string(response.get("Status")) != "SUCCESS":
        raise AuthAdminUnauthorized("MFA verification failed")
    verified_session = _clean_string(response.get("Session"))
    if not verified_session:
        raise AuthAdminUnauthorized("MFA verification failed")
    try:
        challenge_response = _cognito_client().respond_to_auth_challenge(
            ClientId=profile["clientId"],
            ChallengeName="MFA_SETUP",
            Session=verified_session,
            ChallengeResponses={
                "USERNAME": record["username"],
            },
            ClientMetadata=_client_metadata(record["domain"], profile, ""),
        )
    except Exception as exc:
        _log("WARNING", "Cognito MFA setup challenge failed", domain=record["domain"], authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
        raise AuthAdminUnauthorized("Authentication challenge failed") from exc
    return _complete_challenge_response(record, profile, challenge_response)


def _mfa_enroll_start_response(event: dict[str, Any]) -> dict[str, Any]:
    payload = _request_payload(event)
    session, profile = _require_session(event)
    _require_csrf(event, session, profile)
    _require_payload_context_matches_session(payload, session)
    password = _password(payload.get("password"))
    language = _language(payload.get("language"))
    username = _clean_string(session.get("email") or session.get("username"))
    if not username:
        raise AuthAdminUnauthorized()

    try:
        response = _cognito_client().initiate_auth(
            ClientId=profile["clientId"],
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
            },
            ClientMetadata=_client_metadata(session["domain"], profile, language),
        )
    except Exception as exc:
        _log("WARNING", "Cognito MFA enrollment reauth failed", domain=session["domain"], authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
        raise AuthAdminUnauthorized("MFA enrollment failed") from exc

    if _clean_string(response.get("ChallengeName")):
        raise AuthAdminUnauthorized("MFA enrollment requires a fresh sign-in")
    auth_result = response.get("AuthenticationResult") if isinstance(response.get("AuthenticationResult"), dict) else {}
    id_token = _clean_string(auth_result.get("IdToken"))
    access_token = _clean_string(auth_result.get("AccessToken"))
    if not id_token or not access_token:
        raise AuthAdminUnauthorized("MFA enrollment failed")
    claims = _verify_jwt(id_token, profile)
    if not _claims_allowed_for_profile(claims, profile) or _clean_string(claims.get("sub")) != _clean_string(session.get("subject")):
        raise AuthAdminUnauthorized("MFA enrollment failed")

    try:
        setup_response = _cognito_client().associate_software_token(AccessToken=access_token)
    except Exception as exc:
        _log("WARNING", "Cognito voluntary MFA setup failed", domain=session["domain"], authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
        raise AuthAdminUnauthorized("MFA enrollment failed") from exc
    secret_code = _clean_string(setup_response.get("SecretCode"))
    if not secret_code:
        raise AuthAdminUnauthorized("MFA enrollment failed")

    enrollment_value = _random_urlsafe(32)
    enrollment_csrf_value = _random_urlsafe(32)
    now = _now_epoch()
    max_age = DEFAULT_MFA_ENROLLMENT_SECONDS
    record = {
        "sessionIdHash": _sha256(enrollment_value),
        "mfaEnrollmentCsrfHash": _sha256(enrollment_csrf_value),
        "recordType": "authMfaEnrollment",
        "tenantProfileKey": _tenant_profile_key(profile),
        "domain": session["domain"],
        "authProfileId": profile["authProfileId"],
        "environment": profile["environment"],
        "userPoolId": profile["userPoolId"],
        "clientId": profile["clientId"],
        "parentSessionIdHash": session["sessionIdHash"],
        "subject": session["subject"],
        "username": username,
        "emailHash": _sha256(username),
        "cognitoAccessToken": access_token,
        "createdAt": now,
        "expiresAt": now + max_age,
        "revokedAt": None,
    }
    _session_store(profile).put_session(record)
    return _json_response(200, {
        "ok": True,
        "domain": session["domain"],
        "authProfileId": profile["authProfileId"],
        "status": "mfa-enrollment-ready",
        "setup": {
            "method": "software-token",
            "sharedSecret": secret_code,
            "otpauthUri": _totp_otpauth_uri(profile, username, secret_code),
        },
    }, cookies=[
        _cookie(MFA_ENROLLMENT_COOKIE_NAME, enrollment_value, http_only=True, max_age=max_age),
        _cookie(_mfa_enrollment_csrf_cookie_name(profile), enrollment_csrf_value, http_only=False, max_age=max_age),
    ])


def _mfa_enroll_verify_response(event: dict[str, Any]) -> dict[str, Any]:
    payload = _request_payload(event)
    session, profile = _require_session(event)
    _require_payload_context_matches_session(payload, session)
    record = _require_mfa_enrollment(event, session, profile)
    code = _totp_code(payload.get("code"))

    try:
        response = _cognito_client().verify_software_token(
            AccessToken=record["cognitoAccessToken"],
            UserCode=code,
            FriendlyDeviceName=_totp_friendly_device_name(profile),
        )
    except Exception as exc:
        _log("WARNING", "Cognito voluntary MFA verification failed", domain=session["domain"], authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
        raise AuthAdminUnauthorized("MFA verification failed") from exc
    if _clean_string(response.get("Status")) != "SUCCESS":
        raise AuthAdminUnauthorized("MFA verification failed")

    try:
        _cognito_client().set_user_mfa_preference(
            AccessToken=record["cognitoAccessToken"],
            SoftwareTokenMfaSettings={
                "Enabled": True,
                "PreferredMfa": True,
            },
        )
    except Exception as exc:
        _log("WARNING", "Cognito voluntary MFA preference update failed", domain=session["domain"], authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
        raise AuthAdminUnauthorized("MFA verification failed") from exc

    _session_store(profile).revoke_session(record["sessionIdHash"], _now_epoch())
    return _json_response(200, {
        "ok": True,
        "domain": session["domain"],
        "authProfileId": profile["authProfileId"],
        "status": "mfa-enabled",
        "account": _public_account_with_mfa(session, profile, software_token_enabled=True),
        "session": _public_session(session, profile),
    }, cookies=[
        _cookie(MFA_ENROLLMENT_COOKIE_NAME, "", http_only=True, max_age=0),
        _cookie(_mfa_enrollment_csrf_cookie_name(profile), "", http_only=False, max_age=0),
    ])


def _mfa_disable_response(event: dict[str, Any]) -> dict[str, Any]:
    payload = _request_payload(event)
    session, profile = _require_session(event)
    _require_csrf(event, session, profile)
    _require_payload_context_matches_session(payload, session)
    password = _password(payload.get("password"))
    code = _totp_code(payload.get("code"))
    language = _language(payload.get("language"))
    username = _clean_string(session.get("email") or session.get("username"))
    if not username:
        raise AuthAdminUnauthorized()

    try:
        auth_response = _cognito_client().initiate_auth(
            ClientId=profile["clientId"],
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
            },
            ClientMetadata=_client_metadata(session["domain"], profile, language),
        )
    except Exception as exc:
        _log("WARNING", "Cognito MFA disable reauth failed", domain=session["domain"], authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
        raise AuthAdminUnauthorized("MFA disable failed") from exc

    challenge_name = _clean_string(auth_response.get("ChallengeName"))
    if challenge_name:
        if challenge_name != "SOFTWARE_TOKEN_MFA":
            raise AuthAdminUnauthorized("MFA disable requires an unsupported challenge")
        challenge_session = _clean_string(auth_response.get("Session"))
        challenge_parameters = auth_response.get("ChallengeParameters") if isinstance(auth_response.get("ChallengeParameters"), dict) else {}
        challenge_username = _clean_string(challenge_parameters.get("USER_ID_FOR_SRP") or challenge_parameters.get("USERNAME") or username)
        if not challenge_session or not challenge_username:
            raise AuthAdminUnauthorized("MFA disable failed")
        try:
            auth_response = _cognito_client().respond_to_auth_challenge(
                ClientId=profile["clientId"],
                ChallengeName="SOFTWARE_TOKEN_MFA",
                Session=challenge_session,
                ChallengeResponses={
                    "USERNAME": challenge_username,
                    "SOFTWARE_TOKEN_MFA_CODE": code,
                },
                ClientMetadata=_client_metadata(session["domain"], profile, language),
            )
        except Exception as exc:
            _log("WARNING", "Cognito MFA disable challenge failed", domain=session["domain"], authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
            raise AuthAdminUnauthorized("MFA disable failed") from exc

    auth_result = auth_response.get("AuthenticationResult") if isinstance(auth_response.get("AuthenticationResult"), dict) else {}
    id_token = _clean_string(auth_result.get("IdToken"))
    access_token = _clean_string(auth_result.get("AccessToken"))
    if not id_token or not access_token:
        raise AuthAdminUnauthorized("MFA disable failed")
    claims = _verify_jwt(id_token, profile)
    if not _claims_allowed_for_profile(claims, profile) or _clean_string(claims.get("sub")) != _clean_string(session.get("subject")):
        raise AuthAdminUnauthorized("MFA disable failed")

    try:
        _cognito_client().set_user_mfa_preference(
            AccessToken=access_token,
            SoftwareTokenMfaSettings={
                "Enabled": False,
                "PreferredMfa": False,
            },
        )
    except Exception as exc:
        _log("WARNING", "Cognito MFA disable preference update failed", domain=session["domain"], authProfileId=profile["authProfileId"], errorType=type(exc).__name__)
        raise AuthAdminUnauthorized("MFA disable failed") from exc

    return _json_response(200, {
        "ok": True,
        "domain": session["domain"],
        "authProfileId": profile["authProfileId"],
        "status": "mfa-disabled",
        "account": _public_account_with_mfa(session, profile, software_token_enabled=False),
        "session": _public_session(session, profile),
    })


def _complete_challenge_response(record: dict[str, Any], profile: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    next_challenge = _clean_string(response.get("ChallengeName"))
    if next_challenge:
        if next_challenge not in SUPPORTED_CHALLENGES:
            raise AuthAdminUnauthorized("Authentication challenge failed")
        next_session = _clean_string(response.get("Session"))
        if not next_session:
            raise AuthAdminUnauthorized("Authentication challenge failed")
        updated = dict(record)
        updated.update({
            "challengeName": next_challenge,
            "cognitoSession": next_session,
            "challengeParameters": _public_challenge_parameters(
                response.get("ChallengeParameters") if isinstance(response.get("ChallengeParameters"), dict) else {}
            ),
            "updatedAt": _now_epoch(),
        })
        _session_store(profile).put_session(updated)
        return _json_response(200, {
            "ok": True,
            "domain": record["domain"],
            "authProfileId": profile["authProfileId"],
            "status": "challenge-required",
            "challengeName": next_challenge,
            "challengeParameters": updated["challengeParameters"],
        })

    auth_result = response.get("AuthenticationResult") if isinstance(response.get("AuthenticationResult"), dict) else {}
    _session_store(profile).revoke_session(record["sessionIdHash"], _now_epoch())
    return _create_private_session_response(
        record["domain"],
        profile,
        auth_result,
        username=record["username"],
        clear_challenge=True,
    )


def _logout_response(event: dict[str, Any]) -> dict[str, Any]:
    session_value = _cookie_value(event, SESSION_COOKIE_NAME)
    profile_for_cookies: Optional[dict[str, Any]] = None
    if session_value:
        try:
            session, profile = _require_session(event, allow_inactive=True)
            profile_for_cookies = profile
            _require_csrf(event, session, profile)
            _session_store(profile).revoke_session(session["sessionIdHash"], _now_epoch())
        except AuthAdminError:
            pass
    csrf_cookie_name = _csrf_cookie_name(profile_for_cookies) if profile_for_cookies else CSRF_COOKIE_NAME
    mfa_enrollment_csrf_cookie_name = _mfa_enrollment_csrf_cookie_name(profile_for_cookies) if profile_for_cookies else MFA_ENROLLMENT_CSRF_COOKIE_NAME
    return _json_response(200, {
        "ok": True,
        "status": "signed-out",
    }, cookies=[
        _cookie(SESSION_COOKIE_NAME, "", http_only=True, max_age=0),
        _cookie(csrf_cookie_name, "", http_only=False, max_age=0),
        _cookie(MFA_ENROLLMENT_COOKIE_NAME, "", http_only=True, max_age=0),
        _cookie(mfa_enrollment_csrf_cookie_name, "", http_only=False, max_age=0),
    ])


def _approve_user_response(event: dict[str, Any], target_subject: str) -> dict[str, Any]:
    actor, profile = _require_admin_session(event)
    _require_csrf(event, actor, profile)
    if target_subject == actor["subject"]:
        raise AuthAdminError("Users cannot approve themselves")
    payload = _request_payload(event)
    groups = _requested_groups(payload, profile, fallback=None)
    user = _target_user(profile, target_subject)
    updates: dict[str, Any] = {
        "approvalStatus": "approved",
        "enabled": True,
        "approvedAt": _now_epoch(),
        "approvedBy": actor["subject"],
        "updatedAt": _now_epoch(),
    }
    if groups is not None:
        updates["roles"] = _sync_cognito_groups(profile, user, groups)
    updates["sessionVersion"] = _next_session_version(user)
    updated = _session_store(profile).update_user(_user_key(profile, target_subject), updates)
    _write_audit(profile, actor, "user-approved", target_subject, {"roles": updated.get("roles", [])})
    return _json_response(200, {"ok": True, "user": _public_user(updated, profile)})


def _set_user_groups_response(event: dict[str, Any], target_subject: str) -> dict[str, Any]:
    actor, profile = _require_admin_session(event)
    _require_csrf(event, actor, profile)
    if target_subject == actor["subject"]:
        raise AuthAdminError("Users cannot edit their own groups")
    payload = _request_payload(event)
    groups = _requested_groups(payload, profile, fallback=[])
    user = _target_user(profile, target_subject)
    synced_roles = _sync_cognito_groups(profile, user, groups)
    updated = _session_store(profile).update_user(_user_key(profile, target_subject), {
        "roles": synced_roles,
        "sessionVersion": _next_session_version(user),
        "updatedAt": _now_epoch(),
        "updatedBy": actor["subject"],
    })
    _write_audit(profile, actor, "user-groups-updated", target_subject, {"roles": groups})
    return _json_response(200, {"ok": True, "user": _public_user(updated, profile)})


def _set_user_enabled_response(event: dict[str, Any], target_subject: str, *, enabled: bool) -> dict[str, Any]:
    actor, profile = _require_admin_session(event)
    _require_csrf(event, actor, profile)
    if target_subject == actor["subject"]:
        raise AuthAdminError("Users cannot suspend or reactivate themselves")
    user = _target_user(profile, target_subject)
    username = _target_username(user)
    if enabled:
        _cognito_client().admin_enable_user(UserPoolId=profile["userPoolId"], Username=username)
        status = "approved"
        event_type = "user-reactivated"
    else:
        _cognito_client().admin_disable_user(UserPoolId=profile["userPoolId"], Username=username)
        status = "suspended"
        event_type = "user-suspended"
    updated = _session_store(profile).update_user(_user_key(profile, target_subject), {
        "enabled": enabled,
        "approvalStatus": status,
        "sessionVersion": _next_session_version(user),
        "updatedAt": _now_epoch(),
        "updatedBy": actor["subject"],
    })
    _write_audit(profile, actor, event_type, target_subject, {})
    return _json_response(200, {"ok": True, "user": _public_user(updated, profile)})


def _reset_user_mfa_response(event: dict[str, Any], target_subject: str) -> dict[str, Any]:
    actor, profile = _require_admin_session(event)
    _require_csrf(event, actor, profile)
    if target_subject == actor["subject"]:
        raise AuthAdminError("Users cannot reset their own MFA")
    user = _target_user(profile, target_subject)
    username = _target_username(user)
    try:
        _cognito_client().admin_set_user_mfa_preference(
            UserPoolId=profile["userPoolId"],
            Username=username,
            SoftwareTokenMfaSettings={
                "Enabled": False,
                "PreferredMfa": False,
            },
        )
    except Exception as exc:
        _log(
            "WARNING",
            "Cognito admin MFA reset failed",
            domain=profile.get("domain"),
            authProfileId=profile.get("authProfileId"),
            targetSubject=target_subject,
            errorType=type(exc).__name__,
        )
        raise AuthAdminError("MFA reset failed") from exc

    updated = _session_store(profile).update_user(_user_key(profile, target_subject), {
        "sessionVersion": _next_session_version(user),
        "mfaResetAt": _now_epoch(),
        "mfaResetBy": actor["subject"],
        "updatedAt": _now_epoch(),
        "updatedBy": actor["subject"],
    })
    _write_audit(profile, actor, "user-mfa-reset", target_subject, {"method": "SOFTWARE_TOKEN_MFA"})
    return _json_response(200, {
        "ok": True,
        "status": "mfa-reset",
        "user": _public_user(updated, profile),
        "mfa": {
            "status": "disabled",
            "softwareTokenEnabled": False,
            "methods": [],
            "preferredMethod": "",
        },
    })


def _require_session(event: dict[str, Any], *, allow_inactive: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    session_value = _cookie_value(event, SESSION_COOKIE_NAME)
    if not session_value:
        raise AuthAdminUnauthorized()
    session_hash = _sha256(session_value)
    try:
        request_domain, request_auth_profile_id = _request_profile_context(event)
        profile = _profile_for(request_domain, request_auth_profile_id)
    except AuthAdminError as exc:
        raise AuthAdminUnauthorized() from exc
    session = _session_store(profile).get_session(session_hash)
    if not session:
        raise AuthAdminUnauthorized()
    if session.get("revokedAt"):
        raise AuthAdminUnauthorized()
    if int(session.get("expiresAt") or 0) <= _now_epoch():
        raise AuthAdminUnauthorized()
    if session.get("tenantProfileKey") != _tenant_profile_key(profile):
        raise AuthAdminUnauthorized()
    if session.get("domain") != request_domain or session.get("authProfileId") != request_auth_profile_id:
        raise AuthAdminUnauthorized()
    return _refresh_session_from_user_state(session, profile, allow_inactive=allow_inactive), profile


def _require_challenge(
    event: dict[str, Any],
    payload: dict[str, Any],
    *,
    expected_challenge: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    challenge_value = _cookie_value(event, CHALLENGE_COOKIE_NAME)
    if not challenge_value:
        raise _auth_challenge_expired()
    try:
        domain, auth_profile_id = _payload_profile_context(payload)
        profile = _profile_for(domain, auth_profile_id)
    except AuthAdminError as exc:
        raise _auth_challenge_expired() from exc
    record = _session_store(profile).get_session(_sha256(challenge_value))
    if not record:
        raise _auth_challenge_expired()
    if record.get("recordType") != "authChallenge":
        raise _auth_challenge_expired()
    if record.get("revokedAt"):
        raise _auth_challenge_expired()
    if int(record.get("expiresAt") or 0) <= _now_epoch():
        raise _auth_challenge_expired()
    if record.get("tenantProfileKey") != _tenant_profile_key(profile):
        raise _auth_challenge_expired()
    if record.get("domain") != domain or record.get("authProfileId") != auth_profile_id:
        raise _auth_challenge_expired()
    if _clean_string(record.get("challengeName")) != expected_challenge:
        raise AuthAdminError("Authentication challenge type does not match")
    if not _clean_string(record.get("cognitoSession")) or not _clean_string(record.get("username")):
        raise _auth_challenge_expired()
    _require_challenge_csrf(event, record, profile)
    return record, profile


def _auth_challenge_expired() -> AuthAdminUnauthorized:
    return AuthAdminUnauthorized(
        "Authentication challenge expired",
        error_code="auth_challenge_expired",
    )


def _require_mfa_enrollment(event: dict[str, Any], session: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    enrollment_value = _cookie_value(event, MFA_ENROLLMENT_COOKIE_NAME)
    if not enrollment_value:
        raise AuthAdminUnauthorized("MFA enrollment expired")
    record = _session_store(profile).get_session(_sha256(enrollment_value))
    if not record:
        raise AuthAdminUnauthorized("MFA enrollment expired")
    if record.get("recordType") != "authMfaEnrollment":
        raise AuthAdminUnauthorized("MFA enrollment expired")
    if record.get("revokedAt"):
        raise AuthAdminUnauthorized("MFA enrollment expired")
    if int(record.get("expiresAt") or 0) <= _now_epoch():
        raise AuthAdminUnauthorized("MFA enrollment expired")
    if record.get("tenantProfileKey") != _tenant_profile_key(profile):
        raise AuthAdminUnauthorized("MFA enrollment expired")
    if record.get("domain") != session.get("domain") or record.get("authProfileId") != session.get("authProfileId"):
        raise AuthAdminUnauthorized("MFA enrollment expired")
    if record.get("subject") != session.get("subject") or record.get("parentSessionIdHash") != session.get("sessionIdHash"):
        raise AuthAdminUnauthorized("MFA enrollment expired")
    if not _clean_string(record.get("cognitoAccessToken")):
        raise AuthAdminUnauthorized("MFA enrollment expired")
    _require_mfa_enrollment_csrf(event, record, profile)
    return record


def _require_admin_session(event: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    session, profile = _require_session(event)
    if session.get("approvalStatus") != "approved" or session.get("enabled") is not True:
        raise AuthAdminForbidden()
    if not set(_string_list(session.get("roles"))).intersection(set(profile["adminGroups"])):
        raise AuthAdminForbidden()
    return session, profile


def _refresh_session_from_user_state(
    session: dict[str, Any],
    profile: dict[str, Any],
    *,
    allow_inactive: bool = False,
) -> dict[str, Any]:
    user = _session_store(profile).get_user(_user_key(profile, _clean_string(session.get("subject"))))
    if not user:
        raise AuthAdminUnauthorized()
    current_version = int(user.get("sessionVersion") or 1)
    session_version = int(session.get("sessionVersion") or 1)
    if session_version != current_version:
        raise AuthAdminUnauthorized()
    approval_status = _clean_string(user.get("approvalStatus") or profile["defaultUserStatus"])
    enabled = user.get("enabled", True) is True
    if not allow_inactive and (not enabled or approval_status in {"rejected", "suspended"}):
        raise AuthAdminForbidden("Account is not active")
    refreshed = dict(session)
    refreshed.update({
        "username": _clean_string(user.get("username") or session.get("username")),
        "email": _clean_string(user.get("email") or session.get("email")),
        "emailHash": _clean_string(user.get("emailHash") or session.get("emailHash")),
        "roles": [role for role in _string_list(user.get("roles")) if role in profile["allowedGroups"]],
        "approvalStatus": approval_status,
        "enabled": enabled,
        "sessionVersion": current_version,
    })
    return refreshed


def _require_csrf(event: dict[str, Any], session: dict[str, Any], profile: dict[str, Any]) -> None:
    header_value = _header(event, _csrf_header_name(profile))
    cookie_value = _cookie_value(event, _csrf_cookie_name(profile))
    if not header_value or not cookie_value or not hmac.compare_digest(header_value, cookie_value):
        raise AuthAdminForbidden("CSRF validation failed")
    if not hmac.compare_digest(_sha256(header_value), str(session.get("csrfHash") or "")):
        raise AuthAdminForbidden("CSRF validation failed")


def _require_challenge_csrf(event: dict[str, Any], record: dict[str, Any], profile: dict[str, Any]) -> None:
    header_value = _header(event, _csrf_header_name(profile))
    cookie_value = _cookie_value(event, _challenge_csrf_cookie_name(profile))
    if not header_value or not cookie_value or not hmac.compare_digest(header_value, cookie_value):
        raise AuthAdminForbidden("CSRF validation failed")
    if not hmac.compare_digest(_sha256(header_value), str(record.get("challengeCsrfHash") or "")):
        raise AuthAdminForbidden("CSRF validation failed")


def _require_mfa_enrollment_csrf(event: dict[str, Any], record: dict[str, Any], profile: dict[str, Any]) -> None:
    header_value = _header(event, _csrf_header_name(profile))
    cookie_value = _cookie_value(event, _mfa_enrollment_csrf_cookie_name(profile))
    if not header_value or not cookie_value or not hmac.compare_digest(header_value, cookie_value):
        raise AuthAdminForbidden("CSRF validation failed")
    if not hmac.compare_digest(_sha256(header_value), str(record.get("mfaEnrollmentCsrfHash") or "")):
        raise AuthAdminForbidden("CSRF validation failed")


def _require_payload_context_matches_session(payload: dict[str, Any], session: dict[str, Any]) -> None:
    domain, auth_profile_id = _payload_profile_context(payload)
    if domain != session.get("domain") or auth_profile_id != session.get("authProfileId"):
        raise AuthAdminUnauthorized()


def _profile_for(domain: str, auth_profile_id: str) -> dict[str, Any]:
    matches = [
        profile
        for profile in load_config()["profiles"]
        if profile["domain"] == domain and profile["authProfileId"] == auth_profile_id
    ]
    if len(matches) != 1:
        raise AuthAdminNotFound("Auth profile not found")
    profile = matches[0]
    if profile.get("enabled") is not True:
        raise AuthAdminForbidden("Auth profile is disabled")
    if profile["environment"] != _runtime_environment():
        raise AuthAdminForbidden("Auth profile environment does not match this stack")
    return profile


def _request_profile_context(event: dict[str, Any]) -> tuple[str, str]:
    domain = _header(event, CONTEXT_DOMAIN_HEADER) or _query_param(event, "domain")
    auth_profile_id = _header(event, CONTEXT_AUTH_PROFILE_HEADER) or _query_param(event, "authProfileId")
    return _domain(domain), _safe_id(auth_profile_id)


def _payload_profile_context(payload: dict[str, Any]) -> tuple[str, str]:
    return _domain(payload.get("domain")), _safe_id(payload.get("authProfileId"))


def _csrf_cookie_name(profile: Optional[dict[str, Any]]) -> str:
    session_config = profile.get("session") if isinstance(profile, dict) and isinstance(profile.get("session"), dict) else {}
    value = _clean_string(session_config.get("csrfCookieName") if isinstance(session_config, dict) else "")
    return value if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value) else CSRF_COOKIE_NAME


def _challenge_csrf_cookie_name(profile: Optional[dict[str, Any]]) -> str:
    session_config = profile.get("session") if isinstance(profile, dict) and isinstance(profile.get("session"), dict) else {}
    value = _clean_string(session_config.get("challengeCsrfCookieName") if isinstance(session_config, dict) else "")
    return value if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value) else CHALLENGE_CSRF_COOKIE_NAME


def _mfa_enrollment_csrf_cookie_name(profile: Optional[dict[str, Any]]) -> str:
    session_config = profile.get("session") if isinstance(profile, dict) and isinstance(profile.get("session"), dict) else {}
    value = _clean_string(session_config.get("mfaEnrollCsrfCookieName") if isinstance(session_config, dict) else "")
    return value if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value) else MFA_ENROLLMENT_CSRF_COOKIE_NAME


def _csrf_header_name(profile: Optional[dict[str, Any]]) -> str:
    session_config = profile.get("session") if isinstance(profile, dict) and isinstance(profile.get("session"), dict) else {}
    value = _clean_string(session_config.get("csrfHeaderName") if isinstance(session_config, dict) else "")
    return value if re.fullmatch(r"[A-Za-z0-9-]{1,64}", value) else "x-zlp-csrf"


def _upsert_user_state_from_claims(store: Any, profile: dict[str, Any], claims: dict[str, Any], now: int) -> dict[str, Any]:
    subject = _clean_string(claims.get("sub") or claims.get("username"))
    if not subject:
        raise AuthAdminUnauthorized("Sign-in failed")
    roles = [role for role in _string_list(claims.get(profile["groupClaim"])) if role in profile["allowedGroups"]]
    approval_status = profile["defaultUserStatus"]
    if profile["adminGroupsAutoApproved"] and set(roles).intersection(set(profile["adminGroups"])):
        approval_status = "approved"
    item = {
        "tenantProfileKey": _tenant_profile_key(profile),
        "subject": subject,
        "username": _clean_string(claims.get("cognito:username") or claims.get("username") or claims.get("email") or subject),
        "email": _clean_string(claims.get("email")),
        "emailHash": _sha256(_clean_string(claims.get("email"))),
        "roles": roles,
        "approvalStatus": approval_status,
        "enabled": True,
        "sessionVersion": 1,
        "createdAt": now,
        "updatedAt": now,
        "lastSeenAt": now,
    }
    existing = store.put_user_if_absent(_user_key(profile, subject), item)
    if existing:
        update = {
            "roles": roles,
            "email": item["email"],
            "emailHash": item["emailHash"],
            "sessionVersion": int(existing.get("sessionVersion") or 1),
            "lastSeenAt": now,
            "updatedAt": now,
        }
        updated = store.update_user(_user_key(profile, subject), update)
        return updated
    return item


def _claims_allowed_for_profile(claims: dict[str, Any], profile: dict[str, Any]) -> bool:
    return _claims_rejection_code(claims, profile) is None


def _claims_rejection_code(claims: dict[str, Any], profile: dict[str, Any]) -> Optional[str]:
    if not _clean_string(claims.get("sub")):
        return "missing_subject"
    if _clean_string(claims.get("token_use")) != "id":
        return "token_use_mismatch"
    if str(claims.get("iss") or "") != profile["issuer"]:
        return "issuer_mismatch"
    if not set(_string_list(claims.get("aud")) + [_clean_string(claims.get("client_id"))]).intersection(set(profile["audiences"])):
        return "audience_mismatch"
    if profile["tenantClaim"] and str(claims.get(profile["tenantClaim"]) or "") != profile["tenantId"]:
        return "tenant_mismatch"
    if profile["environmentClaim"]:
        environments = _environment_claim_values(
            claims.get(profile["environmentClaim"]),
            profile.get("environmentClaimMode") or "single",
        )
        if profile["environment"] not in environments:
            return "environment_mismatch"
    if not set(_string_list(claims.get(profile["groupClaim"]))).intersection(set(profile["allowedGroups"])):
        return "group_mismatch"
    return None


def _verify_jwt(token: str, profile: dict[str, Any]) -> dict[str, Any]:
    try:
        import jwt  # type: ignore
        from jwt import PyJWKClient  # type: ignore
    except Exception as exc:
        raise AuthAdminUnauthorized("JWT verification dependency is unavailable") from exc
    jwks_url = f"{profile['issuer'].rstrip('/')}/.well-known/jwks.json"
    signing_key = PyJWKClient(jwks_url).get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        issuer=profile["issuer"],
        options={"require": ["exp", "iss", "sub"], "verify_aud": False},
    )
    if not isinstance(claims, dict):
        raise AuthAdminUnauthorized()
    return claims


def _requested_groups(payload: dict[str, Any], profile: dict[str, Any], *, fallback: Optional[list[str]]) -> Optional[list[str]]:
    if "groups" not in payload:
        return fallback
    groups = _string_list(payload.get("groups"))
    if not groups:
        raise AuthAdminError("At least one group is required")
    if not set(groups).issubset(set(profile["manageableGroups"])):
        raise AuthAdminError("Requested groups are not manageable")
    return groups


def _sync_cognito_groups(profile: dict[str, Any], user: dict[str, Any], desired_groups: list[str]) -> list[str]:
    username = _target_username(user)
    current_groups = _cognito_user_groups(profile, username)
    desired = set(desired_groups)
    manageable = set(profile["manageableGroups"])
    cognito = _cognito_client()
    for group in sorted(desired - (current_groups & manageable)):
        cognito.admin_add_user_to_group(
            UserPoolId=profile["userPoolId"],
            Username=username,
            GroupName=group,
        )
    for group in sorted((current_groups & manageable) - desired):
        cognito.admin_remove_user_from_group(
            UserPoolId=profile["userPoolId"],
            Username=username,
            GroupName=group,
        )
    preserved = sorted((current_groups - manageable) & set(profile["allowedGroups"]))
    ordered_desired = [group for group in desired_groups if group in profile["allowedGroups"]]
    return [*ordered_desired, *[group for group in preserved if group not in ordered_desired]]


def _cognito_user_groups(profile: dict[str, Any], username: str) -> set[str]:
    response = _cognito_client().admin_list_groups_for_user(
        UserPoolId=profile["userPoolId"],
        Username=username,
    )
    groups = response.get("Groups") if isinstance(response, dict) else []
    if not isinstance(groups, list):
        return set()
    return {
        _clean_string(group.get("GroupName"))
        for group in groups
        if isinstance(group, dict) and _clean_string(group.get("GroupName"))
    }


def _next_session_version(user: dict[str, Any]) -> int:
    return int(user.get("sessionVersion") or 1) + 1


def _target_user(profile: dict[str, Any], subject: str) -> dict[str, Any]:
    user = _session_store(profile).get_user(_user_key(profile, subject))
    if not user:
        raise AuthAdminNotFound("User not found")
    return user


def _target_username(user: dict[str, Any]) -> str:
    username = _clean_string(user.get("username") or user.get("email") or user.get("subject"))
    if not username:
        raise AuthAdminError("Target user is missing username")
    return username


def _public_challenge_parameters(parameters: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for source_key, target_key in (
        ("MFAS_CAN_SETUP", "mfasCanSetup"),
        ("MFAS_CAN_SELECT", "mfasCanSelect"),
    ):
        value = parameters.get(source_key)
        if isinstance(value, list):
            output[target_key] = [_clean_string(item) for item in value if _clean_string(item)]
        elif _clean_string(value):
            output[target_key] = _clean_string(value)
    return output


def _totp_otpauth_uri(profile: dict[str, Any], username: str, secret_code: str) -> str:
    issuer = _totp_issuer(profile)
    account_name = _totp_account_name(profile, username, issuer)
    label = f"{issuer}:{account_name}" if issuer else account_name
    return (
        f"otpauth://totp/{quote(label, safe='')}"
        f"?secret={quote(secret_code, safe='')}"
        f"&issuer={quote(issuer, safe='')}"
        "&algorithm=SHA1&digits=6&period=30"
    )


def _totp_issuer(profile: dict[str, Any]) -> str:
    totp = _totp_config(profile)
    fallback = _clean_string(profile.get("displayName") or profile.get("domain") or "Zoolanding")
    return _totp_text(totp.get("issuer"), fallback, "mfa.totp.issuer", max_length=64)


def _totp_account_name(profile: dict[str, Any], username: str, issuer: str) -> str:
    totp = _totp_config(profile)
    template = _totp_text(totp.get("accountLabelTemplate"), "{username}", "mfa.totp.accountLabelTemplate", max_length=160)
    context = {
        "issuer": issuer,
        "domain": _clean_string(profile.get("domain")),
        "authProfileId": _clean_string(profile.get("authProfileId")),
        "tenantId": _clean_string(profile.get("tenantId")),
        "username": _clean_string(username),
        "email": _clean_string(username),
    }
    rendered = TOTP_TEMPLATE_RE.sub(lambda match: context[match.group(1)], template).strip()
    return _totp_text(rendered, _clean_string(username), "mfa.totp.accountLabelTemplate", max_length=160)


def _totp_friendly_device_name(profile: dict[str, Any]) -> str:
    totp = _totp_config(profile)
    return _totp_text(totp.get("friendlyDeviceName"), f"{_totp_issuer(profile)} authenticator", "mfa.totp.friendlyDeviceName", max_length=128)


def _totp_config(profile: dict[str, Any]) -> dict[str, Any]:
    mfa = profile.get("mfa") if isinstance(profile.get("mfa"), dict) else {}
    totp = mfa.get("totp") if isinstance(mfa.get("totp"), dict) else {}
    for key in ("issuer", "accountLabelTemplate", "friendlyDeviceName"):
        if key in totp:
            _totp_text(totp.get(key), "", f"mfa.totp.{key}", max_length=160)
    template = _clean_string(totp.get("accountLabelTemplate"))
    unknown = [key for key in TOTP_TEMPLATE_RE.findall(template) if key not in TOTP_TEMPLATE_KEYS]
    if unknown:
        raise AuthAdminConfigError(f"mfa.totp.accountLabelTemplate has unsupported placeholder {unknown[0]}")
    return totp


def _totp_text(value: Any, fallback: str, field_name: str, *, max_length: int) -> str:
    text = _clean_string(value)
    if not text:
        text = fallback
    if CONTROL_CHAR_RE.search(text) or len(text) > max_length:
        raise AuthAdminConfigError(f"{field_name} is invalid")
    return text


def _write_audit(profile: dict[str, Any], actor: dict[str, Any], event_type: str, target_subject: str, details: dict[str, Any]) -> None:
    now = _now_epoch()
    item = {
        "tenantProfileKey": _tenant_profile_key(profile),
        "auditKey": f"AUDIT#{now}#{_sha256(event_type + target_subject)[:12]}#{_random_urlsafe(8)}",
        "eventType": event_type,
        "actorSubject": actor["subject"],
        "targetSubject": target_subject,
        "domain": profile["domain"],
        "authProfileId": profile["authProfileId"],
        "environment": profile["environment"],
        "details": details,
        "createdAt": now,
    }
    _session_store(profile).write_audit(item)


def _public_session(session: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile": _public_account(session, profile),
        "provider": profile["provider"],
        "expiresAtEpochMs": int(session.get("expiresAt") or 0) * 1000,
    }


def _public_account(session: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    return _public_user({
        "subject": session.get("subject"),
        "email": session.get("email"),
        "roles": session.get("roles"),
        "approvalStatus": session.get("approvalStatus"),
        "enabled": session.get("enabled"),
        "tenantId": session.get("tenantId"),
        "environment": session.get("environment"),
        "domain": session.get("domain"),
        "authProfileId": session.get("authProfileId"),
    }, profile)


def _public_account_with_mfa(
    session: dict[str, Any],
    profile: dict[str, Any],
    *,
    software_token_enabled: Optional[bool] = None,
) -> dict[str, Any]:
    account = _public_account(session, profile)
    account["mfa"] = _public_mfa_state(session, profile, software_token_enabled=software_token_enabled)
    return account


def _public_mfa_state(
    session: dict[str, Any],
    profile: dict[str, Any],
    *,
    software_token_enabled: Optional[bool] = None,
) -> dict[str, Any]:
    if software_token_enabled is not None:
        return {
            "status": "enabled" if software_token_enabled else "disabled",
            "softwareTokenEnabled": software_token_enabled,
            "methods": ["SOFTWARE_TOKEN_MFA"] if software_token_enabled else [],
            "preferredMethod": "SOFTWARE_TOKEN_MFA" if software_token_enabled else "",
        }

    username = _clean_string(session.get("username") or session.get("email") or session.get("subject"))
    if not username:
        return _unknown_mfa_state()

    try:
        response = _cognito_client().admin_get_user(
            UserPoolId=profile["userPoolId"],
            Username=username,
        )
    except Exception as exc:
        _log(
            "WARNING",
            "Cognito MFA state read failed",
            domain=session.get("domain"),
            authProfileId=profile.get("authProfileId"),
            errorType=type(exc).__name__,
        )
        return _unknown_mfa_state()

    methods = [
        method
        for method in _string_list(response.get("UserMFASettingList") if isinstance(response, dict) else None)
        if method in {"SOFTWARE_TOKEN_MFA", "SMS_MFA", "EMAIL_OTP"}
    ]
    preferred = _clean_string(response.get("PreferredMfaSetting") if isinstance(response, dict) else "")
    software_enabled = "SOFTWARE_TOKEN_MFA" in methods or preferred == "SOFTWARE_TOKEN_MFA"
    return {
        "status": "enabled" if software_enabled else "disabled",
        "softwareTokenEnabled": software_enabled,
        "methods": methods,
        "preferredMethod": preferred if preferred in {"SOFTWARE_TOKEN_MFA", "SMS_MFA", "EMAIL_OTP"} else "",
    }


def _unknown_mfa_state() -> dict[str, Any]:
    return {
        "status": "unknown",
        "softwareTokenEnabled": None,
        "methods": [],
        "preferredMethod": "",
    }


def _public_user(user: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    roles = [role for role in _string_list(user.get("roles")) if role in profile["allowedGroups"]]
    return {
        "subject": _clean_string(user.get("subject")),
        "email": _clean_string(user.get("email")),
        "roles": roles,
        "approvalStatus": _clean_string(user.get("approvalStatus") or "pending"),
        "enabled": user.get("enabled", True) is True,
        "environment": profile["environment"],
        "isAdmin": bool(set(roles).intersection(set(profile["adminGroups"]))),
    }


def _sort_users(users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(users, key=lambda user: (_clean_string(user.get("email")), _clean_string(user.get("subject"))))


class DynamoAuthAdminStore:
    def __init__(self, profile: dict[str, Any]):
        self.profile = profile
        tables = profile.get("tables") if isinstance(profile.get("tables"), dict) else {}
        self.session_table_name = _clean_string(tables.get("sessionTableName") or os.getenv(SESSION_TABLE_ENV))
        self.user_table_name = _clean_string(tables.get("userStateTableName") or os.getenv(USER_STATE_TABLE_ENV))
        self.audit_table_name = _clean_string(tables.get("auditTableName") or os.getenv(AUDIT_TABLE_ENV))
        if not self.session_table_name or not self.user_table_name or not self.audit_table_name:
            raise AuthAdminConfigError("Auth admin DynamoDB table names are required")
        self.dynamodb = _dynamodb_resource()

    def put_session(self, item: dict[str, Any]) -> None:
        self._session_table().put_item(Item=_without_none(item))

    def get_session(self, session_id_hash: str) -> Optional[dict[str, Any]]:
        response = self._session_table().get_item(Key={"sessionIdHash": session_id_hash})
        return response.get("Item")

    def revoke_session(self, session_id_hash: str, revoked_at: int) -> None:
        self._session_table().update_item(
            Key={"sessionIdHash": session_id_hash},
            UpdateExpression="SET revokedAt = :revokedAt",
            ExpressionAttributeValues={":revokedAt": revoked_at},
        )

    def put_user_if_absent(self, key: tuple[str, str], item: dict[str, Any]) -> Optional[dict[str, Any]]:
        tenant_profile_key, user_key = key
        table_item = _without_none({**item, "tenantProfileKey": tenant_profile_key, "userKey": user_key})
        try:
            self._user_table().put_item(
                Item=table_item,
                ConditionExpression="attribute_not_exists(tenantProfileKey) AND attribute_not_exists(userKey)",
            )
            return None
        except Exception:
            return self.get_user(key)

    def get_user(self, key: tuple[str, str]) -> Optional[dict[str, Any]]:
        response = self._user_table().get_item(Key={"tenantProfileKey": key[0], "userKey": key[1]})
        return response.get("Item")

    def list_users(self, tenant_profile_key: str) -> list[dict[str, Any]]:
        response = self._user_table().query(
            KeyConditionExpression="tenantProfileKey = :tenantProfileKey",
            ExpressionAttributeValues={":tenantProfileKey": tenant_profile_key},
            Limit=200,
        )
        return response.get("Items", [])

    def update_user(self, key: tuple[str, str], updates: dict[str, Any]) -> dict[str, Any]:
        names = {f"#k{index}": field for index, field in enumerate(updates)}
        values = {f":v{index}": value for index, value in enumerate(updates.values())}
        set_expression = ", ".join(f"{name} = {value}" for name, value in zip(names.keys(), values.keys()))
        response = self._user_table().update_item(
            Key={"tenantProfileKey": key[0], "userKey": key[1]},
            UpdateExpression=f"SET {set_expression}",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
            ReturnValues="ALL_NEW",
        )
        return response.get("Attributes", {})

    def write_audit(self, item: dict[str, Any]) -> None:
        self._audit_table().put_item(Item=_without_none(item))

    def _session_table(self) -> Any:
        return self.dynamodb.Table(self.session_table_name)

    def _user_table(self) -> Any:
        return self.dynamodb.Table(self.user_table_name)

    def _audit_table(self) -> Any:
        return self.dynamodb.Table(self.audit_table_name)


def _session_store(profile: Optional[dict[str, Any]] = None) -> DynamoAuthAdminStore:
    if profile is None:
        raise AuthAdminConfigError("Auth profile is required for session store")
    return DynamoAuthAdminStore(profile)


def _cognito_client() -> Any:
    import boto3  # type: ignore

    return boto3.client("cognito-idp")


def _dynamodb_resource() -> Any:
    import boto3  # type: ignore

    return boto3.resource("dynamodb")


def _request_payload(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("body")
    if event.get("isBase64Encoded") is True and isinstance(raw, str):
        raw = base64.b64decode(raw).decode("utf-8")
    if not raw:
        return {}
    payload = json.loads(str(raw))
    if not isinstance(payload, dict):
        raise AuthAdminError("Request body must be a JSON object")
    return payload


def _method(event: dict[str, Any]) -> str:
    return _clean_string((event.get("requestContext") or {}).get("http", {}).get("method") or event.get("httpMethod")).upper()


def _path(event: dict[str, Any]) -> str:
    path = _clean_string(event.get("rawPath") or event.get("path") or (event.get("requestContext") or {}).get("http", {}).get("path"))
    stage = _clean_string((event.get("requestContext") or {}).get("stage"))
    if stage and path.startswith(f"/{stage}/"):
        path = path[len(stage) + 1:]
    return path or "/"


def _admin_user_operation(path: str) -> tuple[str, str]:
    match = re.fullmatch(r"/auth/admin/users/([^/]+)/(approve|groups|suspend|reactivate|mfa/reset)", path)
    if not match:
        raise AuthAdminNotFound("Auth admin route not found")
    return match.group(1), match.group(2)


def _header(event: dict[str, Any], name: str) -> str:
    headers = event.get("headers") if isinstance(event.get("headers"), dict) else {}
    for key, value in headers.items():
        if str(key).lower() == name.lower():
            return _clean_string(value)
    return ""


def _query_param(event: dict[str, Any], name: str) -> str:
    params = event.get("queryStringParameters") if isinstance(event.get("queryStringParameters"), dict) else {}
    for key, value in params.items():
        if str(key) == name:
            return _clean_string(value)
    return ""


def _cookie_value(event: dict[str, Any], name: str) -> str:
    cookie_headers = list(event.get("cookies") or [])
    header_cookie = _header(event, "cookie")
    if header_cookie:
        cookie_headers.extend(part.strip() for part in header_cookie.split(";"))
    for cookie in cookie_headers:
        if not isinstance(cookie, str) or "=" not in cookie:
            continue
        key, value = cookie.split("=", 1)
        if key.strip() == name:
            return value.strip()
    return ""


def _json_response(status_code: int, payload: dict[str, Any], *, cookies: Optional[list[str]] = None) -> dict[str, Any]:
    response = {
        "statusCode": status_code,
        "headers": {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
        },
        "body": json.dumps(payload, separators=(",", ":")),
    }
    if cookies:
        response["cookies"] = cookies
    return response


def _cookie(name: str, value: str, *, http_only: bool, max_age: int) -> str:
    parts = [
        f"{name}={value}",
        "HttpOnly" if http_only else "",
        "Secure",
        "SameSite=Lax",
        "Path=/",
        f"Max-Age={max_age}",
    ]
    return "; ".join(part for part in parts if part)


def _client_metadata(domain: str, profile: dict[str, Any], language: str) -> dict[str, str]:
    metadata = {
        "domain": domain,
        "authProfileId": profile["authProfileId"],
        "environment": profile["environment"],
    }
    if language:
        metadata["language"] = language
    return metadata


def _tenant_profile_key(profile: dict[str, Any]) -> str:
    return f"{profile['domain']}#{profile['authProfileId']}#{profile['environment']}"


def _user_key(profile: dict[str, Any], subject: str) -> tuple[str, str]:
    return (_tenant_profile_key(profile), f"USER#{subject}")


def _without_none(item: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in item.items() if value is not None}


def _domain(value: Any) -> str:
    domain = _clean_string(value).lower()
    if not DOMAIN_RE.fullmatch(domain):
        raise AuthAdminError("Invalid domain")
    return domain


def _safe_id(value: Any) -> str:
    safe_id = _clean_string(value)
    if not SAFE_ID_RE.fullmatch(safe_id):
        raise AuthAdminError("Invalid auth profile id")
    return safe_id


def _email(value: Any) -> str:
    email = _clean_string(value).lower()
    if not email or len(email) > 320 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise AuthAdminError("Invalid email")
    return email


def _password(value: Any) -> str:
    password = str(value or "")
    if not password or len(password) > 4096 or CONTROL_OR_WHITESPACE_RE.search(password):
        raise AuthAdminError("Invalid password")
    return password


def _totp_code(value: Any) -> str:
    code = _clean_string(value)
    if not re.fullmatch(r"[0-9]{6}", code):
        raise AuthAdminError("Invalid MFA code")
    return code


def _language(value: Any) -> str:
    language = _clean_string(value).lower()
    return language if re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]{2,8})?", language) else ""


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [_clean_string(value)] if _clean_string(value) else []
    if not isinstance(value, list):
        raise AuthAdminConfigError("Expected a list of strings")
    output = []
    for item in value:
        text = _clean_string(item)
        if not text:
            raise AuthAdminConfigError("String lists cannot contain empty values")
        output.append(text)
    return output


def _positive_int(value: Any, default: int) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except Exception as exc:
        raise AuthAdminConfigError("Expected a positive integer") from exc
    if parsed <= 0:
        raise AuthAdminConfigError("Expected a positive integer")
    return parsed


def _runtime_environment() -> str:
    return _environment_alias(os.getenv(ENVIRONMENT_ENV, "prod"))


def _environment_alias(value: Any) -> str:
    environment = _clean_string(value).lower()
    aliases = {
        "production": "prod",
        "testing": "test",
        "development": "dev",
    }
    environment = aliases.get(environment, environment)
    if environment not in AUTH_ENVIRONMENTS:
        raise AuthAdminConfigError("Environment must be dev, test, or prod")
    return environment


def _environment_claim_values(value: Any, mode: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        raw_values = value
    else:
        raw_text = _clean_string(value)
        if not raw_text:
            return []
        raw_values = re.split(r"[,\s]+", raw_text) if mode == "list" else [raw_text]

    environments = []
    aliases = {
        "production": "prod",
        "testing": "test",
        "development": "dev",
    }
    for raw_value in raw_values:
        environment = aliases.get(_clean_string(raw_value).lower(), _clean_string(raw_value).lower())
        if environment in AUTH_ENVIRONMENTS and environment not in environments:
            environments.append(environment)
    return environments


def _clean_string(value: Any) -> str:
    return str(value or "").strip()


def _sha256(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _random_urlsafe(byte_count: int = 32) -> str:
    return secrets.token_urlsafe(byte_count)


def _now_epoch() -> int:
    return int(time.time())


def _reject_secret_like_config(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            key_compact = key_text.replace("-", "_").lower()
            if any(fragment in key_compact for fragment in SECRET_KEY_FRAGMENTS):
                raise AuthAdminConfigError(f"Secret-like config key is not allowed at {path}.{key_text}")
            _reject_secret_like_config(child, f"{path}.{key_text}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_like_config(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if any(marker in value for marker in SECRET_VALUE_MARKERS):
            raise AuthAdminConfigError(f"Secret-like config value is not allowed at {path}")


def _log(level: str, message: str, **kwargs: Any) -> None:
    configured = str(os.getenv("LOG_LEVEL", "INFO")).upper()
    order = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
    if order.get(level, 20) < order.get(configured, 20):
        return
    print(json.dumps({"level": level, "message": message, **kwargs}, separators=(",", ":")))
