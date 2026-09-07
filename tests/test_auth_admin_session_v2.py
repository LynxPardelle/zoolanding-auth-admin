import copy
import hashlib
import importlib
import json
import os
import sys
import types
import unittest
from unittest.mock import patch

import auth_admin_current_user_v2 as current_user
import lambda_function as auth_admin


try:
    session_v2 = importlib.import_module("auth_admin_session_v2")
except ModuleNotFoundError as exc:
    if exc.name != "auth_admin_session_v2":
        raise
    session_v2 = None


ADMIN_HOST = "admin-test.thehairnarrative.com"
ADMIN_ORIGIN = f"https://{ADMIN_HOST}"
NOW = 1_800_000_000
COOKIE_NAMESPACE = "endefiz7dkk635k6di6k"
SESSION_COOKIE = f"__Host-zlp_session_{COOKIE_NAMESPACE}"
CHALLENGE_COOKIE = f"__Host-zlp_challenge_{COOKIE_NAMESPACE}"
ENROLLMENT_COOKIE = f"__Host-zlp_mfa_enroll_{COOKIE_NAMESPACE}"
CSRF_COOKIE = f"zlp_csrf_{COOKIE_NAMESPACE}"
CHALLENGE_CSRF_COOKIE = f"zlp_challenge_csrf_{COOKIE_NAMESPACE}"
ENROLLMENT_CSRF_COOKIE = f"zlp_mfa_enroll_csrf_{COOKIE_NAMESPACE}"
SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 12 * 60 * 60
EPHEMERAL_SECONDS = 5 * 60
FAILURE_WINDOW_SECONDS = 15 * 60

SCOPE = dict(current_user.APPROVED_SCOPE)
DEFAULT_CLAIMS = {
    "sub": "owner-123",
    "cognito:username": "owner@example.test",
    "email": "owner@example.test",
    "token_use": "id",
    "cognito:groups": ["journal-owner"],
    "exp": NOW + SESSION_ABSOLUTE_SECONDS + 60,
    "iat": NOW - 60,
    "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_THNTEST",
    "aud": "thnv2client",
}
REQUIRED_PROVIDER_SEAMS = (
    "_session_store",
    "_current_user_client",
    "_cognito_client",
    "_verify_id_token",
    "_now_epoch",
    "_random_urlsafe",
)


class AwsProviderError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def _contract_available():
    return (
        session_v2 is not None
        and callable(getattr(session_v2, "lambda_handler", None))
        and all(callable(getattr(session_v2, name, None)) for name in REQUIRED_PROVIDER_SEAMS)
    )


CONTRACT_AVAILABLE = _contract_available()


def hash_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def response_body(response):
    return json.loads(response.get("body") or "{}")


def response_cookies(response):
    return list(response.get("cookies") or [])


def cookie_value(cookies, name):
    prefix = f"{name}="
    cookie = next(value for value in cookies if value.startswith(prefix))
    return cookie.split(";", 1)[0].split("=", 1)[1]


def cookie_line(cookies, name):
    prefix = f"{name}="
    return next(value for value in cookies if value.startswith(prefix))


def v2_event(
    method,
    path,
    body=None,
    *,
    host=ADMIN_HOST,
    origin=ADMIN_ORIGIN,
    source_ip="203.0.113.10",
    cookies=None,
    headers=None,
):
    request_headers = {
        "host": host,
        "origin": origin,
        "x-zlp-viewer-ip": source_ip,
        "x-forwarded-host": ADMIN_HOST,
    }
    request_headers.update(headers or {})
    return {
        "version": "2.0",
        "routeKey": f"{method} {path}",
        "rawPath": path,
        "headers": request_headers,
        "cookies": list(cookies or []),
        "requestContext": {
            "authorizer": {
                "lambda": {"originVerified": True, "viewerIp": source_ip}
            },
            "http": {
                "method": method,
                "path": path,
                "sourceIp": source_ip,
            },
            "requestId": "request-v2-1",
        },
        "body": json.dumps(body) if body is not None else None,
    }


def signin_event(email="owner@example.test", password="ValidPass123!", **event_overrides):
    return v2_event(
        "POST",
        "/auth-v2/session/signin",
        {
            "email": email,
            "password": password,
            "language": "es",
        },
        **event_overrides,
    )


def current_user_state(
    *,
    subject="owner-123",
    account_purpose="client-owner",
    session_version=3,
    enabled=True,
):
    return {
        "contractVersion": 1,
        "scope": copy.deepcopy(SCOPE),
        "subject": subject,
        "accountPurpose": account_purpose,
        "sessionVersion": session_version,
        "enabled": enabled,
    }


def current_user_storage_item(state):
    return {
        "pk": current_user.APPROVED_PARTITION_KEY,
        "sk": f"SUBJECT#{state['subject']}",
        **copy.deepcopy(state),
    }


class FakeCognito:
    def __init__(
        self,
        *,
        auth_response=None,
        auth_error=None,
        challenge_response=None,
        challenge_error=None,
        associate_response=None,
        verify_response=None,
        current_user_enabled=True,
        current_user_groups=None,
        current_user_subject="owner-123",
        current_username="owner@example.test",
        current_user_error=None,
        current_group_pages=None,
    ):
        self.calls = []
        self.auth_response = auth_response or {
            "AuthenticationResult": {"IdToken": "valid-v2-id-token"}
        }
        self.auth_error = auth_error
        self.challenge_response = challenge_response or {
            "AuthenticationResult": {"IdToken": "valid-v2-id-token"}
        }
        self.challenge_error = challenge_error
        self.associate_response = associate_response or {
            "SecretCode": "ABCDEFGHIJKLMNOP",
            "Session": "associated-cognito-session",
        }
        self.verify_response = verify_response or {
            "Status": "SUCCESS",
            "Session": "verified-cognito-session",
        }
        self.current_user_enabled = current_user_enabled
        self.current_user_groups = list(
            current_user_groups
            if current_user_groups is not None
            else ["journal-owner"]
        )
        self.current_user_subject = current_user_subject
        self.current_username = current_username
        self.current_user_error = current_user_error
        self.current_group_pages = copy.deepcopy(current_group_pages)

    def admin_initiate_auth(self, **kwargs):
        self.calls.append(("admin_initiate_auth", copy.deepcopy(kwargs)))
        if self.auth_error is not None:
            raise self.auth_error
        return copy.deepcopy(self.auth_response)

    def admin_respond_to_auth_challenge(self, **kwargs):
        self.calls.append(("admin_respond_to_auth_challenge", copy.deepcopy(kwargs)))
        if self.challenge_error is not None:
            raise self.challenge_error
        return copy.deepcopy(self.challenge_response)

    def associate_software_token(self, **kwargs):
        self.calls.append(("associate_software_token", copy.deepcopy(kwargs)))
        return copy.deepcopy(self.associate_response)

    def verify_software_token(self, **kwargs):
        self.calls.append(("verify_software_token", copy.deepcopy(kwargs)))
        return copy.deepcopy(self.verify_response)

    def admin_get_user(self, **kwargs):
        self.calls.append(("admin_get_user", copy.deepcopy(kwargs)))
        if self.current_user_error is not None:
            raise self.current_user_error
        return {
            "Username": self.current_username,
            "Enabled": self.current_user_enabled,
            "UserAttributes": [
                {"Name": "sub", "Value": self.current_user_subject},
            ],
        }

    def admin_list_groups_for_user(self, **kwargs):
        self.calls.append(("admin_list_groups_for_user", copy.deepcopy(kwargs)))
        if self.current_group_pages is not None:
            page_index = len(
                [name for name, _kwargs in self.calls if name == "admin_list_groups_for_user"]
            ) - 1
            return copy.deepcopy(self.current_group_pages[page_index])
        return {
            "Groups": [
                {"GroupName": group_name}
                for group_name in self.current_user_groups
            ]
        }


class FakeV2Store:
    """In-memory boundary expected by auth_admin_session_v2.

    The fake deliberately records consistent reads, conditional claims, rotations,
    and hashed throttle dimensions. It contains no behavior specific to HTTP or
    Cognito, keeping policy in the production module rather than in the fake.

    This fake is sequential. Production must implement claim, release, consume,
    failure-window counters, and session rotation as atomic conditional storage
    operations so concurrent requests cannot both authorize the same state.
    """

    def __init__(self, *, users=None):
        self.sessions = {}
        self.ephemeral = {}
        self.current_users = {}
        self.failure_events = {}
        self.calls = []
        self.claim_counter = 0
        for state in users or [current_user_state()]:
            self.current_users[state["subject"]] = copy.deepcopy(state)

    def put_session(self, item):
        value = copy.deepcopy(item)
        self.calls.append(("put_session", value))
        key = value["sessionIdHash"]
        if key in self.sessions:
            raise RuntimeError("conditional session collision")
        self.sessions[key] = value

    def get_session(self, session_id_hash, *, consistent_read):
        self.calls.append(("get_session", session_id_hash, consistent_read))
        value = self.sessions.get(session_id_hash)
        return copy.deepcopy(value) if value is not None else None

    def touch_session(
        self,
        session_id_hash,
        *,
        now,
        idle_expires_at,
        absolute_expires_at,
        subject,
        account_purpose,
        session_version,
    ):
        self.calls.append(
            (
                "touch_session",
                session_id_hash,
                now,
                idle_expires_at,
                absolute_expires_at,
                subject,
                account_purpose,
                session_version,
            )
        )
        item = self.sessions.get(session_id_hash)
        current = self.current_users.get(subject)
        if (
            item is None
            or item.get("revokedAt") is not None
            or item.get("subject") != subject
            or item.get("accountPurpose") != account_purpose
            or item.get("sessionVersion") != session_version
            or item.get("absoluteExpiresAt") != absolute_expires_at
            or current is None
            or current.get("enabled") is not True
            or current.get("accountPurpose") != account_purpose
            or current.get("sessionVersion") != session_version
        ):
            raise RuntimeError("conditional session touch failed")
        item["lastSeenAt"] = now
        item["idleExpiresAt"] = idle_expires_at
        return copy.deepcopy(item)

    def rotate_session(self, old_session_id_hash, new_item, *, now):
        value = copy.deepcopy(new_item)
        self.calls.append(("rotate_session", old_session_id_hash, value, now))
        old = self.sessions.get(old_session_id_hash)
        if old is None or old.get("revokedAt") is not None:
            raise RuntimeError("conditional session rotation failed")
        if value["sessionIdHash"] in self.sessions:
            raise RuntimeError("conditional session collision")
        old["revokedAt"] = now
        self.sessions[value["sessionIdHash"]] = value

    def revoke_session(self, session_id_hash, *, now):
        self.calls.append(("revoke_session", session_id_hash, now))
        item = self.sessions.get(session_id_hash)
        if item is None or item.get("revokedAt") is not None:
            return False
        item["revokedAt"] = now
        return True

    def put_ephemeral(self, item):
        value = copy.deepcopy(item)
        self.calls.append(("put_ephemeral", value))
        key = value["stateIdHash"]
        if key in self.ephemeral:
            raise RuntimeError("conditional ephemeral collision")
        self.ephemeral[key] = value

    def get_ephemeral(self, state_id_hash, *, consistent_read):
        self.calls.append(("get_ephemeral", state_id_hash, consistent_read))
        value = self.ephemeral.get(state_id_hash)
        return copy.deepcopy(value) if value is not None else None

    def claim_ephemeral(
        self, state_id_hash, *, expected_type, expected_binding_hash, now
    ):
        self.calls.append(
            (
                "claim_ephemeral",
                state_id_hash,
                expected_type,
                expected_binding_hash,
                now,
            )
        )
        value = self.ephemeral.get(state_id_hash)
        if (
            value is None
            or value.get("recordType") != expected_type
            or value.get("stateBindingHash") != expected_binding_hash
            or value.get("claimedAt") is not None
            or value.get("consumedAt") is not None
            or value.get("expiresAt", 0) <= now
        ):
            return None
        self.claim_counter += 1
        claim_token = hash_text(
            f"{state_id_hash}:{now}:{self.claim_counter}"
        )[:32]
        value["claimedAt"] = now
        value["claimTokenHash"] = hash_text(claim_token)
        claimed = copy.deepcopy(value)
        claimed["claimToken"] = claim_token
        return claimed

    def release_ephemeral_claim(
        self,
        state_id_hash,
        *,
        now,
        claim_token=None,
        expected_binding_hash=None,
    ):
        self.calls.append(
            (
                "release_ephemeral_claim",
                state_id_hash,
                now,
                claim_token,
                expected_binding_hash,
            )
        )
        value = self.ephemeral.get(state_id_hash)
        if (
            value is None
            or value.get("claimedAt") is None
            or value.get("consumedAt") is not None
            or value.get("stateBindingHash") != expected_binding_hash
            or (
                claim_token is not None
                and value.get("claimTokenHash") != hash_text(claim_token)
            )
        ):
            return False
        value["claimedAt"] = None
        value.pop("claimTokenHash", None)
        return True

    def consume_ephemeral_claim(
        self,
        state_id_hash,
        *,
        now,
        claim_token=None,
        expected_binding_hash=None,
    ):
        self.calls.append(
            (
                "consume_ephemeral_claim",
                state_id_hash,
                now,
                claim_token,
                expected_binding_hash,
            )
        )
        value = self.ephemeral.get(state_id_hash)
        if (
            value is None
            or value.get("claimedAt") is None
            or value.get("consumedAt") is not None
            or value.get("expiresAt", 0) <= now
            or value.get("stateBindingHash") != expected_binding_hash
            or (
                claim_token is not None
                and value.get("claimTokenHash") != hash_text(claim_token)
            )
        ):
            return False
        value["consumedAt"] = now
        value.pop("claimTokenHash", None)
        value.pop("cognitoSession", None)
        value.pop("username", None)
        return True

    def transition_ephemeral_claim(
        self,
        state_id_hash,
        *,
        expected_type,
        expected_binding_hash,
        expected_account_hash,
        claim_token,
        now,
        next_item,
    ):
        value = self.ephemeral.get(state_id_hash)
        successor = copy.deepcopy(next_item)
        self.calls.append(
            (
                "transition_ephemeral_claim",
                state_id_hash,
                expected_type,
                expected_binding_hash,
                expected_account_hash,
                now,
                successor,
            )
        )
        if (
            value is None
            or value.get("recordType") != expected_type
            or value.get("stateBindingHash") != expected_binding_hash
            or value.get("accountHash") != expected_account_hash
            or value.get("claimTokenHash") != hash_text(claim_token)
            or value.get("claimedAt") is None
            or value.get("consumedAt") is not None
            or value.get("expiresAt", 0) <= now
            or successor.get("accountHash") != expected_account_hash
        ):
            return False
        if successor.get("recordType") == "authSessionV2":
            target = self.sessions
            key = successor["sessionIdHash"]
        else:
            target = self.ephemeral
            key = successor["stateIdHash"]
        if key in target:
            return False
        value["consumedAt"] = now
        value.pop("claimTokenHash", None)
        value.pop("cognitoSession", None)
        value.pop("username", None)
        target[key] = successor
        return True

    def count_failures(self, operation, dimension, key_hash, *, now, window_seconds):
        self.calls.append(
            (
                "count_failures",
                operation,
                dimension,
                key_hash,
                now,
                window_seconds,
            )
        )
        cutoff = now - window_seconds
        key = (operation, dimension, key_hash)
        retained = [timestamp for timestamp in self.failure_events.get(key, []) if timestamp > cutoff]
        self.failure_events[key] = retained
        return len(retained)

    def record_failure(self, operation, dimension, key_hash, *, now, window_seconds):
        self.calls.append(
            (
                "record_failure",
                operation,
                dimension,
                key_hash,
                now,
                window_seconds,
            )
        )
        self.count_failures(
            operation,
            dimension,
            key_hash,
            now=now,
            window_seconds=window_seconds,
        )
        self.failure_events.setdefault((operation, dimension, key_hash), []).append(now)

    def get_item(self, **kwargs):
        request = copy.deepcopy(kwargs)
        self.calls.append(("current_user_get", request))
        raw_key = current_user.unmarshal_item(request["Key"])
        subject = raw_key["sk"].removeprefix("SUBJECT#")
        state = self.current_users.get(subject)
        if state is None:
            return {}
        return {"Item": current_user.marshal_item(current_user_storage_item(state))}


class ContractPresenceTests(unittest.TestCase):
    def test_task_015_v2_module_handler_and_provider_seams_exist(self):
        self.assertIsNotNone(
            session_v2,
            "TASK-015 RED: auth_admin_session_v2.py has not been implemented",
        )
        self.assertTrue(
            callable(getattr(session_v2, "lambda_handler", None)),
            "TASK-015 RED: auth_admin_session_v2.lambda_handler has not been implemented",
        )
        missing = [
            name
            for name in REQUIRED_PROVIDER_SEAMS
            if not callable(getattr(session_v2, name, None))
        ]
        self.assertEqual(missing, [], f"TASK-015 RED: missing provider seams: {missing}")


@unittest.skipUnless(CONTRACT_AVAILABLE, "TASK-015 v2 contract is not implemented yet")
class AuthAdminSessionV2Tests(unittest.TestCase):
    def run_v2(
        self,
        event,
        *,
        store=None,
        cognito=None,
        claims=None,
        now=NOW,
        random_values=None,
    ):
        store = store or FakeV2Store()
        cognito = cognito or FakeCognito()
        tokens = iter(
            random_values
            or (
                "session-token",
                "session-csrf",
                "challenge-token",
                "challenge-csrf",
                "enrollment-token",
                "enrollment-csrf",
                "rotated-session-token",
                "rotated-csrf",
            )
        )
        with (
            patch.object(
                session_v2,
                "_require_active_service_binding",
                return_value={"bindingStatus": "active"},
            ),
            patch.object(session_v2, "_session_store", return_value=store),
            patch.object(session_v2, "_current_user_client", return_value=store),
            patch.object(session_v2, "_cognito_client", return_value=cognito),
            patch.object(
                session_v2,
                "_cognito_configuration",
                return_value=("us-east-1", "us-east-1_THNTEST", "thnv2client"),
            ),
            patch.object(
                session_v2,
                "_verify_id_token",
                return_value=copy.deepcopy(claims or DEFAULT_CLAIMS),
            ),
            patch.object(session_v2, "_now_epoch", return_value=now),
            patch.object(session_v2, "_random_urlsafe", side_effect=lambda *_: next(tokens)),
        ):
            response = session_v2.lambda_handler(event, object())
        return response, store, cognito

    def seed_session(
        self,
        store,
        *,
        raw_session="live-session-token",
        raw_csrf="live-csrf-token",
        subject="owner-123",
        account_purpose="client-owner",
        cognito_username="owner@example.test",
        session_version=3,
        created_at=NOW - 60,
        last_seen_at=NOW - 60,
        idle_expires_at=NOW + SESSION_IDLE_SECONDS - 60,
        absolute_expires_at=NOW + SESSION_ABSOLUTE_SECONDS - 60,
    ):
        record = {
            "recordType": "authSessionV2",
            "sessionIdHash": hash_text(raw_session),
            "csrfHash": hash_text(raw_csrf),
            "scope": copy.deepcopy(SCOPE),
            "subject": subject,
            "accountHash": hash_text("owner@example.test"),
            "accountPurpose": account_purpose,
            "cognitoUsername": cognito_username,
            "sessionVersion": session_version,
            "roles": ["journal-owner"],
            "createdAt": created_at,
            "lastSeenAt": last_seen_at,
            "idleExpiresAt": idle_expires_at,
            "absoluteExpiresAt": absolute_expires_at,
            "expiresAt": absolute_expires_at,
            "revokedAt": None,
        }
        store.put_session(record)
        return record

    def seed_challenge(
        self,
        store,
        *,
        raw_state="challenge-token",
        raw_csrf="challenge-csrf",
        email="owner@example.test",
        challenge_name="SOFTWARE_TOKEN_MFA",
    ):
        record = {
            "recordType": "authChallengeV2",
            "stateIdHash": hash_text(raw_state),
            "csrfHash": hash_text(raw_csrf),
            "scope": copy.deepcopy(SCOPE),
            "accountHash": hash_text(email.strip().lower()),
            "username": email,
            "challengeName": challenge_name,
            "cognitoSession": "private-cognito-session",
            "createdAt": NOW,
            "expiresAt": NOW + EPHEMERAL_SECONDS,
            "claimedAt": None,
            "consumedAt": None,
        }
        record["stateBindingHash"] = session_v2._ephemeral_state_binding_hash(record)
        store.put_ephemeral(record)
        return record

    def test_session_me_get_requires_cloudfront_forwarded_host(self):
        event = v2_event("GET", "/auth-v2/session/me")
        event["headers"].pop("origin")
        event["headers"].pop("x-forwarded-host")

        response, store, cognito = self.run_v2(event)

        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(
            response_body(response),
            {
                "ok": False,
                "error": "Request origin denied",
                "errorCode": "auth_origin_denied",
            },
        )
        self.assertEqual(store.calls, [])
        self.assertEqual(cognito.calls, [])

        string_claim = v2_event("GET", "/auth-v2/session/me")
        string_claim["requestContext"]["authorizer"]["lambda"][
            "originVerified"
        ] = "true"
        response, store, cognito = self.run_v2(string_claim)
        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(store.calls, [])
        self.assertEqual(cognito.calls, [])

    def test_cloudfront_forwarded_host_and_exact_cors_headers_are_supported(self):
        event = v2_event(
            "GET",
            "/auth-v2/session/me",
            host="auth-admin.execute-api.us-east-1.amazonaws.com",
            headers={"x-forwarded-host": ADMIN_HOST},
        )

        response, store, cognito = self.run_v2(event)

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(
            response["headers"]["access-control-allow-origin"],
            ADMIN_ORIGIN,
        )
        self.assertEqual(
            response["headers"]["access-control-allow-credentials"],
            "true",
        )
        self.assertEqual(response["headers"]["vary"], "Origin")
        self.assertEqual(store.calls, [])
        self.assertEqual(cognito.calls, [])

        wrong_forwarded = copy.deepcopy(event)
        wrong_forwarded["headers"]["x-forwarded-host"] = (
            "test.zoolandingpage.com.mx"
        )
        denied, denied_store, denied_cognito = self.run_v2(wrong_forwarded)
        self.assertEqual(denied["statusCode"], 403)
        self.assertEqual(denied_store.calls, [])
        self.assertEqual(denied_cognito.calls, [])

    def test_forwarded_origin_and_viewer_ip_require_verified_authorizer_context(self):
        event = v2_event(
            "POST",
            "/auth-v2/session/signin",
            {"email": "owner@example.test", "password": "ValidPass123!"},
            host="auth-admin.execute-api.us-east-1.amazonaws.com",
            headers={"x-forwarded-host": ADMIN_HOST},
        )
        event["requestContext"].pop("authorizer")

        response, store, cognito = self.run_v2(event)

        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(store.calls, [])
        self.assertEqual(cognito.calls, [])

        direct_peer_only = v2_event(
            "POST",
            "/auth-v2/session/signin",
            {"email": "owner@example.test", "password": "ValidPass123!"},
        )
        direct_peer_only["headers"].pop("x-zlp-viewer-ip")
        direct_peer_only["requestContext"]["authorizer"]["lambda"].pop("viewerIp")
        response, store, cognito = self.run_v2(direct_peer_only)
        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(store.calls, [])
        self.assertEqual(cognito.calls, [])

        forged_header = v2_event(
            "POST",
            "/auth-v2/session/signin",
            {"email": "owner@example.test", "password": "ValidPass123!"},
            source_ip="203.0.113.9",
        )
        forged_header["headers"]["x-zlp-viewer-ip"] = "198.51.100.88"
        with patch.object(session_v2, "_require_active_service_binding"):
            self.assertEqual(session_v2._source_ip(forged_header), "203.0.113.9")

        wrong_origin = copy.deepcopy(event)
        wrong_origin["headers"]["origin"] = "https://test.zoolandingpage.com.mx"
        denied, denied_store, denied_cognito = self.run_v2(wrong_origin)
        self.assertEqual(denied["statusCode"], 403)
        self.assertEqual(denied_store.calls, [])
        self.assertEqual(denied_cognito.calls, [])

    def test_cookie_names_scope_and_ttls_are_exact(self):
        store = FakeV2Store()
        self.seed_challenge(store)
        response, _, _ = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/challenge/respond",
                {"code": "123456"},
                cookies=[
                    f"{CHALLENGE_COOKIE}=challenge-token",
                    f"{CHALLENGE_CSRF_COOKIE}=challenge-csrf",
                ],
                headers={"x-zlp-csrf": "challenge-csrf"},
            ),
            store=store,
            random_values=("session-token", "session-csrf"),
        )

        self.assertEqual(response["statusCode"], 200)
        cookies = response_cookies(response)
        session_line = cookie_line(cookies, SESSION_COOKIE)
        csrf_line = cookie_line(cookies, CSRF_COOKIE)
        for flag in ("HttpOnly", "Secure", "SameSite=Lax", "Path=/", "Max-Age=43200"):
            self.assertIn(flag, session_line)
        self.assertNotIn("HttpOnly", csrf_line)
        for flag in ("Secure", "SameSite=Lax", "Path=/", "Max-Age=43200"):
            self.assertIn(flag, csrf_line)
        self.assertNotIn("Domain=", "\n".join(cookies))

        record = next(iter(store.sessions.values()))
        self.assertEqual(record["createdAt"], NOW)
        self.assertEqual(record["lastSeenAt"], NOW)
        self.assertEqual(record["idleExpiresAt"], NOW + SESSION_IDLE_SECONDS)
        self.assertEqual(record["absoluteExpiresAt"], NOW + SESSION_ABSOLUTE_SECONDS)

    def test_challenge_and_enrollment_cookies_are_suffixed_host_only_and_five_minutes(self):
        challenge_cognito = FakeCognito(
            auth_response={
                "ChallengeName": "MFA_SETUP",
                "Session": "private-mfa-setup-session",
                "ChallengeParameters": {"USERNAME": "owner@example.test"},
            }
        )
        challenge_response, store, _ = self.run_v2(
            signin_event(),
            cognito=challenge_cognito,
            random_values=("challenge-token", "challenge-csrf"),
        )
        challenge_cookies = response_cookies(challenge_response)
        challenge_line = cookie_line(challenge_cookies, CHALLENGE_COOKIE)
        challenge_csrf_line = cookie_line(challenge_cookies, CHALLENGE_CSRF_COOKIE)
        self.assertIn("HttpOnly", challenge_line)
        self.assertNotIn("HttpOnly", challenge_csrf_line)
        self.assertIn("Max-Age=300", challenge_line)
        self.assertIn("Max-Age=300", challenge_csrf_line)
        self.assertNotIn("Domain=", "\n".join(challenge_cookies))

        setup_response, _, _ = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/mfa/setup",
                {},
                cookies=[
                    f"{CHALLENGE_COOKIE}=challenge-token",
                    f"{CHALLENGE_CSRF_COOKIE}=challenge-csrf",
                ],
                headers={"x-zlp-csrf": "challenge-csrf"},
            ),
            store=store,
            cognito=challenge_cognito,
            random_values=("enrollment-token", "enrollment-csrf"),
        )
        enrollment_cookies = response_cookies(setup_response)
        enrollment_line = cookie_line(enrollment_cookies, ENROLLMENT_COOKIE)
        enrollment_csrf_line = cookie_line(enrollment_cookies, ENROLLMENT_CSRF_COOKIE)
        self.assertIn("HttpOnly", enrollment_line)
        self.assertNotIn("HttpOnly", enrollment_csrf_line)
        self.assertIn("Max-Age=300", enrollment_line)
        self.assertIn("Max-Age=300", enrollment_csrf_line)
        self.assertNotIn("Domain=", "\n".join(enrollment_cookies))
        self.assertEqual(
            setup_response["headers"],
            {
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
        )
        setup_body = response_body(setup_response)
        self.assertEqual(
            setup_body,
            {
                "ok": True,
                "status": "mfa-enrollment-required",
                "mfa": {
                    "method": "SOFTWARE_TOKEN_MFA",
                    "issuer": "The Hair Narrative",
                    "accountLabel": "Journal owner",
                    "manualSetupKey": "ABCDEFGHIJKLMNOP",
                },
            },
        )
        self.assertNotIn("otpauth", setup_response["body"].lower())
        self.assertNotIn("associated-cognito-session", setup_response["body"])
        self.assertNotIn("ABCDEFGHIJKLMNOP", json.dumps(store.ephemeral, sort_keys=True))
        self.assertTrue(
            all(item["expiresAt"] == NOW + EPHEMERAL_SECONDS for item in store.ephemeral.values())
        )

    def test_new_password_required_rotates_to_a_single_use_mfa_setup_challenge(self):
        cognito = FakeCognito(
            auth_response={
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "Session": "private-new-password-session",
                "ChallengeParameters": {"USERNAME": "owner@example.test"},
            },
            challenge_response={
                "ChallengeName": "MFA_SETUP",
                "Session": "private-mfa-setup-session",
                "ChallengeParameters": {"USERNAME": "owner@example.test"},
            },
        )
        signin, store, _ = self.run_v2(
            signin_event(),
            cognito=cognito,
            random_values=("password-challenge", "password-csrf"),
        )
        self.assertEqual(response_body(signin).get("challengeName"), "NEW_PASSWORD_REQUIRED")

        response, _, _ = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/challenge/respond",
                {"newPassword": "ReplacementPass456!"},
                cookies=[
                    f"{CHALLENGE_COOKIE}=password-challenge",
                    f"{CHALLENGE_CSRF_COOKIE}=password-csrf",
                ],
                headers={"x-zlp-csrf": "password-csrf"},
            ),
            store=store,
            cognito=cognito,
            random_values=("mfa-challenge", "mfa-challenge-csrf"),
        )

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response_body(response).get("challengeName"), "MFA_SETUP")
        challenge_calls = [
            kwargs
            for name, kwargs in cognito.calls
            if name == "admin_respond_to_auth_challenge"
        ]
        self.assertEqual(len(challenge_calls), 1)
        self.assertEqual(challenge_calls[0]["ChallengeName"], "NEW_PASSWORD_REQUIRED")
        self.assertEqual(challenge_calls[0]["UserPoolId"], "us-east-1_THNTEST")
        self.assertEqual(challenge_calls[0]["ClientId"], "thnv2client")
        self.assertEqual(
            challenge_calls[0]["ChallengeResponses"],
            {
                "USERNAME": "owner@example.test",
                "NEW_PASSWORD": "ReplacementPass456!",
            },
        )
        old_record = store.ephemeral[hash_text("password-challenge")]
        next_record = store.ephemeral[hash_text("mfa-challenge")]
        self.assertEqual(old_record["consumedAt"], NOW)
        self.assertEqual(next_record["challengeName"], "MFA_SETUP")
        self.assertEqual(next_record["cognitoSession"], "private-mfa-setup-session")
        self.assertIsNone(next_record["claimedAt"])
        self.assertEqual(store.sessions, {})
        cookies = response_cookies(response)
        self.assertEqual(cookie_value(cookies, CHALLENGE_COOKIE), "mfa-challenge")
        self.assertEqual(cookie_value(cookies, CHALLENGE_CSRF_COOKIE), "mfa-challenge-csrf")

    def test_successful_mfa_verification_consumes_enrollment_and_creates_session(self):
        store = FakeV2Store()
        self.seed_challenge(store, challenge_name="MFA_SETUP")
        cognito = FakeCognito()
        setup, _, _ = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/mfa/setup",
                {},
                cookies=[
                    f"{CHALLENGE_COOKIE}=challenge-token",
                    f"{CHALLENGE_CSRF_COOKIE}=challenge-csrf",
                ],
                headers={"x-zlp-csrf": "challenge-csrf"},
            ),
            store=store,
            cognito=cognito,
            random_values=("enrollment-token", "enrollment-csrf"),
        )
        self.assertEqual(setup["statusCode"], 200)

        response, _, _ = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/mfa/verify",
                {"code": "123456"},
                cookies=[
                    f"{ENROLLMENT_COOKIE}=enrollment-token",
                    f"{ENROLLMENT_CSRF_COOKIE}=enrollment-csrf",
                ],
                headers={"x-zlp-csrf": "enrollment-csrf"},
            ),
            store=store,
            cognito=cognito,
            random_values=("mfa-session-token", "mfa-session-csrf"),
        )

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response_body(response).get("status"), "signed-in")
        verify_calls = [kwargs for name, kwargs in cognito.calls if name == "verify_software_token"]
        self.assertEqual(
            verify_calls,
            [
                {
                    "Session": "associated-cognito-session",
                    "UserCode": "123456",
                    "FriendlyDeviceName": "The Hair Narrative",
                }
            ],
        )
        challenge_calls = [
            kwargs
            for name, kwargs in cognito.calls
            if name == "admin_respond_to_auth_challenge"
        ]
        self.assertEqual(challenge_calls[-1]["ChallengeName"], "MFA_SETUP")
        self.assertEqual(challenge_calls[-1]["Session"], "verified-cognito-session")
        enrollment = store.ephemeral[hash_text("enrollment-token")]
        self.assertEqual(enrollment["consumedAt"], NOW)
        self.assertIn(hash_text("mfa-session-token"), store.sessions)
        current_reads = [call[1] for call in store.calls if call[0] == "current_user_get"]
        self.assertEqual(len(current_reads), 1)
        self.assertIs(current_reads[0]["ConsistentRead"], True)
        cookies = response_cookies(response)
        self.assertEqual(cookie_value(cookies, SESSION_COOKIE), "mfa-session-token")
        self.assertEqual(cookie_value(cookies, CSRF_COOKIE), "mfa-session-csrf")
        self.assertIn("Max-Age=0", cookie_line(cookies, ENROLLMENT_COOKIE))
        self.assertIn("Max-Age=0", cookie_line(cookies, ENROLLMENT_CSRF_COOKIE))
        self.assertNotIn("ABCDEFGHIJKLMNOP", response["body"])
        self.assertNotIn("associated-cognito-session", response["body"])

    def test_every_v2_request_requires_the_exact_host_and_origin_before_providers(self):
        cases = (
            {"headers": {"x-forwarded-host": "test.zoolandingpage.com.mx"}},
            {"headers": {"x-forwarded-host": "admin-test.thehairnarrative.com:443"}},
            {"origin": "https://test.zoolandingpage.com.mx"},
            {"origin": "http://admin-test.thehairnarrative.com"},
            {"origin": ""},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                store = FakeV2Store()
                cognito = FakeCognito()
                response, _, _ = self.run_v2(
                    signin_event(**overrides), store=store, cognito=cognito
                )
                self.assertEqual(response["statusCode"], 403)
                self.assertEqual(response_body(response).get("errorCode"), "auth_origin_denied")
                self.assertEqual(cognito.calls, [])
                self.assertEqual(store.calls, [])

    def test_options_are_not_an_auth_admin_route_on_the_same_origin(self):
        for path in (
            "/auth-v2/session/signin",
            "/auth-v2/unknown-route",
        ):
            with self.subTest(path=path):
                response, store, cognito = self.run_v2(v2_event("OPTIONS", path))

                self.assertEqual(response["statusCode"], 404)
                self.assertEqual(response_body(response).get("errorCode"), "not_found")
                self.assertEqual(store.calls, [])
                self.assertEqual(cognito.calls, [])

    def test_signin_authentication_result_without_mfa_is_rejected(self):
        store = FakeV2Store()
        response, _, cognito = self.run_v2(
            signin_event(),
            store=store,
            cognito=FakeCognito(
                auth_response={
                    "AuthenticationResult": {"IdToken": "valid-but-no-mfa-id-token"}
                }
            ),
        )

        self.assertEqual(response["statusCode"], 503)
        self.assertEqual(response_body(response).get("errorCode"), "auth_unavailable")
        self.assertEqual(store.sessions, {})
        signin_calls = [
            kwargs
            for name, kwargs in cognito.calls
            if name == "admin_initiate_auth"
        ]
        self.assertEqual(len(signin_calls), 1)
        self.assertEqual(
            signin_calls[0],
            {
                "UserPoolId": "us-east-1_THNTEST",
                "ClientId": "thnv2client",
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "owner@example.test",
                    "PASSWORD": "ValidPass123!",
                },
                "ClientMetadata": {
                    "environment": "test",
                    "authProfileId": "journal-owner",
                },
            },
        )

    def test_signin_failures_are_enumeration_safe_and_use_only_hashed_account_dimensions(self):
        results = []
        stores = []
        for email, provider_error in (
            ("missing@example.test", RuntimeError("private user-not-found sentinel")),
            ("owner@example.test", RuntimeError("private wrong-password sentinel")),
        ):
            store = FakeV2Store()
            response, _, _ = self.run_v2(
                signin_event(email=email),
                store=store,
                cognito=FakeCognito(auth_error=provider_error),
            )
            results.append((response["statusCode"], response["body"]))
            stores.append((store, email))

        self.assertEqual(results[0], results[1])
        status, rendered = results[0]
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(rendered).get("errorCode"), "auth_failed")
        self.assertNotIn("missing@example.test", rendered)
        self.assertNotIn("owner@example.test", rendered)
        self.assertNotIn("sentinel", rendered)
        for store, email in stores:
            dimensions = [key[2] for key in store.failure_events]
            self.assertIn(hash_text(email), dimensions)
            self.assertNotIn(email, repr(store.failure_events))

    def test_signin_throttle_is_five_per_account_and_ten_per_source_ip_for_fifteen_minutes(self):
        account_store = FakeV2Store()
        account_cognito = FakeCognito(auth_error=RuntimeError("invalid credentials"))
        for attempt in range(5):
            response, _, _ = self.run_v2(
                signin_event(source_ip=f"203.0.113.{attempt + 1}"),
                store=account_store,
                cognito=account_cognito,
            )
            self.assertEqual(response["statusCode"], 401)
        blocked, _, _ = self.run_v2(
            signin_event(source_ip="203.0.113.99"),
            store=account_store,
            cognito=account_cognito,
        )
        self.assertEqual(blocked["statusCode"], 429)
        self.assertEqual(response_body(blocked).get("errorCode"), "auth_throttled")
        self.assertEqual(
            [name for name, _ in account_cognito.calls].count("admin_initiate_auth"), 5
        )

        ip_store = FakeV2Store()
        ip_cognito = FakeCognito(auth_error=RuntimeError("invalid credentials"))
        for attempt in range(10):
            response, _, _ = self.run_v2(
                signin_event(email=f"owner-{attempt}@example.test", source_ip="203.0.113.50"),
                store=ip_store,
                cognito=ip_cognito,
            )
            self.assertEqual(response["statusCode"], 401)
        blocked, _, _ = self.run_v2(
            signin_event(email="owner-11@example.test", source_ip="203.0.113.50"),
            store=ip_store,
            cognito=ip_cognito,
        )
        self.assertEqual(blocked["statusCode"], 429)
        self.assertEqual(
            [name for name, _ in ip_cognito.calls].count("admin_initiate_auth"), 10
        )

        reopened, _, _ = self.run_v2(
            signin_event(source_ip="203.0.113.99"),
            store=account_store,
            cognito=account_cognito,
            now=NOW + FAILURE_WINDOW_SECONDS,
        )
        self.assertEqual(reopened["statusCode"], 401)

    def test_signin_ip_throttle_uses_request_context_source_ip_and_ignores_xff(self):
        store = FakeV2Store()
        cognito = FakeCognito(auth_error=RuntimeError("invalid credentials"))
        source_ip = "203.0.113.42"
        spoofed_ips = []
        for attempt in range(10):
            spoofed = f"198.51.100.{attempt + 1}"
            spoofed_ips.append(spoofed)
            response, _, _ = self.run_v2(
                signin_event(
                    email=f"xff-owner-{attempt}@example.test",
                    source_ip=source_ip,
                    headers={"x-forwarded-for": spoofed},
                ),
                store=store,
                cognito=cognito,
            )
            self.assertEqual(response["statusCode"], 401)

        blocked, _, _ = self.run_v2(
            signin_event(
                email="xff-owner-blocked@example.test",
                source_ip=source_ip,
                headers={"x-forwarded-for": "192.0.2.250"},
            ),
            store=store,
            cognito=cognito,
        )
        self.assertEqual(blocked["statusCode"], 429)
        self.assertEqual(
            [name for name, _ in cognito.calls].count("admin_initiate_auth"),
            10,
        )
        ip_dimensions = {
            key_hash
            for operation, dimension, key_hash in store.failure_events
            if operation == "signin" and dimension == "ip"
        }
        self.assertEqual(ip_dimensions, {hash_text(source_ip)})
        self.assertTrue(
            all(hash_text(spoofed) not in ip_dimensions for spoofed in spoofed_ips)
        )

    def test_challenge_throttle_is_five_per_account_and_five_per_ip(self):
        account_store = FakeV2Store()
        self.seed_challenge(account_store)
        account_cognito = FakeCognito(challenge_error=RuntimeError("invalid totp"))
        for attempt in range(5):
            response, _, _ = self.run_v2(
                v2_event(
                    "POST",
                    "/auth-v2/session/challenge/respond",
                    {"code": "000000"},
                    source_ip=f"203.0.113.{attempt + 1}",
                    cookies=[
                        f"{CHALLENGE_COOKIE}=challenge-token",
                        f"{CHALLENGE_CSRF_COOKIE}=challenge-csrf",
                    ],
                    headers={"x-zlp-csrf": "challenge-csrf"},
                ),
                store=account_store,
                cognito=account_cognito,
            )
            self.assertEqual(response["statusCode"], 401)
        blocked, _, _ = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/challenge/respond",
                {"code": "000000"},
                source_ip="203.0.113.99",
                cookies=[
                    f"{CHALLENGE_COOKIE}=challenge-token",
                    f"{CHALLENGE_CSRF_COOKIE}=challenge-csrf",
                ],
                headers={"x-zlp-csrf": "challenge-csrf"},
            ),
            store=account_store,
            cognito=account_cognito,
        )
        self.assertEqual(blocked["statusCode"], 429)
        self.assertEqual(
            [name for name, _ in account_cognito.calls].count(
                "admin_respond_to_auth_challenge"
            ),
            5,
        )
        self.assertEqual(
            [call[0] for call in account_store.calls].count(
                "release_ephemeral_claim"
            ),
            6,
        )

        ip_store = FakeV2Store()
        ip_cognito = FakeCognito(challenge_error=RuntimeError("invalid totp"))
        for attempt in range(5):
            token = f"challenge-token-{attempt}"
            csrf = f"challenge-csrf-{attempt}"
            email = f"owner-{attempt}@example.test"
            self.seed_challenge(
                ip_store,
                raw_state=token,
                raw_csrf=csrf,
                email=email,
            )
            response, _, _ = self.run_v2(
                v2_event(
                    "POST",
                    "/auth-v2/session/challenge/respond",
                    {"code": "000000"},
                    source_ip="203.0.113.60",
                    cookies=[
                        f"{CHALLENGE_COOKIE}={token}",
                        f"{CHALLENGE_CSRF_COOKIE}={csrf}",
                    ],
                    headers={"x-zlp-csrf": csrf},
                ),
                store=ip_store,
                cognito=ip_cognito,
            )
            self.assertEqual(response["statusCode"], 401)
        sixth_token = "challenge-token-sixth"
        sixth_csrf = "challenge-csrf-sixth"
        self.seed_challenge(
            ip_store,
            raw_state=sixth_token,
            raw_csrf=sixth_csrf,
            email="owner-sixth@example.test",
        )
        blocked, _, _ = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/challenge/respond",
                {"code": "000000"},
                source_ip="203.0.113.60",
                cookies=[
                    f"{CHALLENGE_COOKIE}={sixth_token}",
                    f"{CHALLENGE_CSRF_COOKIE}={sixth_csrf}",
                ],
                headers={"x-zlp-csrf": sixth_csrf},
            ),
            store=ip_store,
            cognito=ip_cognito,
        )
        self.assertEqual(blocked["statusCode"], 429)

    def test_successful_challenge_claim_is_single_use_and_replay_never_reaches_cognito(self):
        store = FakeV2Store()
        self.seed_challenge(store)
        cognito = FakeCognito()
        event = v2_event(
            "POST",
            "/auth-v2/session/challenge/respond",
            {"code": "123456"},
            cookies=[
                f"{CHALLENGE_COOKIE}=challenge-token",
                f"{CHALLENGE_CSRF_COOKIE}=challenge-csrf",
            ],
            headers={"x-zlp-csrf": "challenge-csrf"},
        )

        first, _, _ = self.run_v2(
            event,
            store=store,
            cognito=cognito,
            random_values=("session-after-mfa", "csrf-after-mfa"),
        )
        replay, _, _ = self.run_v2(event, store=store, cognito=cognito)

        self.assertEqual(first["statusCode"], 200)
        self.assertEqual(replay["statusCode"], 401)
        self.assertEqual(
            [name for name, _ in cognito.calls].count("admin_respond_to_auth_challenge"),
            1,
        )
        claimed = store.ephemeral[hash_text("challenge-token")]
        self.assertEqual(claimed["claimedAt"], NOW)
        self.assertEqual(claimed["consumedAt"], NOW)
        self.assertTrue(any(call[0] == "claim_ephemeral" for call in store.calls))
        self.assertTrue(
            any(call[0] == "transition_ephemeral_claim" for call in store.calls)
        )

    def test_client_owner_session_rejects_missing_journal_owner_group(self):
        claims = copy.deepcopy(DEFAULT_CLAIMS)
        claims.pop("cognito:groups")
        store = FakeV2Store()
        self.seed_challenge(store)

        response, _, _ = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/challenge/respond",
                {"code": "123456"},
                cookies=[
                    f"{CHALLENGE_COOKIE}=challenge-token",
                    f"{CHALLENGE_CSRF_COOKIE}=challenge-csrf",
                ],
                headers={"x-zlp-csrf": "challenge-csrf"},
            ),
            store=store,
            claims=claims,
        )

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(response_body(response).get("errorCode"), "auth_failed")
        self.assertEqual(store.sessions, {})

    def test_client_owner_session_rejects_additional_group(self):
        claims = {
            **copy.deepcopy(DEFAULT_CLAIMS),
            "cognito:groups": ["journal-owner", "unexpected-admin"],
        }
        store = FakeV2Store()
        self.seed_challenge(store)

        response, _, _ = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/challenge/respond",
                {"code": "123456"},
                cookies=[
                    f"{CHALLENGE_COOKIE}=challenge-token",
                    f"{CHALLENGE_CSRF_COOKIE}=challenge-csrf",
                ],
                headers={"x-zlp-csrf": "challenge-csrf"},
            ),
            store=store,
            claims=claims,
        )

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(response_body(response).get("errorCode"), "auth_failed")
        self.assertEqual(store.sessions, {})

    def test_client_owner_session_requires_a_safe_signed_cognito_username(self):
        for invalid_username in (None, "", " owner@example.test", "x" * 129, "bad\nname"):
            with self.subTest(invalid_username=invalid_username):
                claims = copy.deepcopy(DEFAULT_CLAIMS)
                if invalid_username is None:
                    claims.pop("cognito:username")
                else:
                    claims["cognito:username"] = invalid_username
                store = FakeV2Store()
                self.seed_challenge(store)

                response, _, cognito = self.run_v2(
                    v2_event(
                        "POST",
                        "/auth-v2/session/challenge/respond",
                        {"code": "123456"},
                        cookies=[
                            f"{CHALLENGE_COOKIE}=challenge-token",
                            f"{CHALLENGE_CSRF_COOKIE}=challenge-csrf",
                        ],
                        headers={"x-zlp-csrf": "challenge-csrf"},
                    ),
                    store=store,
                    claims=claims,
                )

                self.assertEqual(response["statusCode"], 401)
                self.assertEqual(store.sessions, {})
                self.assertNotIn("admin_get_user", [name for name, _ in cognito.calls])

    def test_new_session_revalidates_membership_and_keeps_provider_username_private(self):
        store = FakeV2Store()
        self.seed_challenge(store)
        denied, _, _ = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/challenge/respond",
                {"code": "123456"},
                cookies=[
                    f"{CHALLENGE_COOKIE}=challenge-token",
                    f"{CHALLENGE_CSRF_COOKIE}=challenge-csrf",
                ],
                headers={"x-zlp-csrf": "challenge-csrf"},
            ),
            store=store,
            cognito=FakeCognito(current_user_groups=[]),
        )
        self.assertEqual(denied["statusCode"], 401)
        self.assertEqual(store.sessions, {})

        allowed_store = FakeV2Store()
        self.seed_challenge(allowed_store)
        allowed, _, _ = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/challenge/respond",
                {"code": "123456"},
                cookies=[
                    f"{CHALLENGE_COOKIE}=challenge-token",
                    f"{CHALLENGE_CSRF_COOKIE}=challenge-csrf",
                ],
                headers={"x-zlp-csrf": "challenge-csrf"},
            ),
            store=allowed_store,
            cognito=FakeCognito(),
        )
        self.assertEqual(allowed["statusCode"], 200)
        persisted = next(iter(allowed_store.sessions.values()))
        self.assertEqual(persisted["cognitoUsername"], "owner@example.test")
        self.assertNotIn("owner@example.test", json.dumps(response_body(allowed)))

    def test_me_uses_strong_current_user_read_and_enforces_purpose_version_and_enabled(self):
        cases = (
            (current_user_state(), 200),
            (current_user_state(account_purpose="qa"), 401),
            (current_user_state(session_version=4), 401),
            (current_user_state(enabled=False), 401),
        )
        for state, expected_status in cases:
            with self.subTest(state=state):
                store = FakeV2Store(users=[state])
                self.seed_session(store)
                response, _, _ = self.run_v2(
                    v2_event(
                        "GET",
                        "/auth-v2/session/me",
                        cookies=[f"{SESSION_COOKIE}=live-session-token"],
                    ),
                    store=store,
                )
                self.assertEqual(response["statusCode"], expected_status)
                current_reads = [call[1] for call in store.calls if call[0] == "current_user_get"]
                self.assertEqual(len(current_reads), 1)
                self.assertIs(current_reads[0]["ConsistentRead"], True)

    def test_me_denies_a_version_bump_between_current_read_and_session_touch(self):
        class ConcurrentVersionBumpStore(FakeV2Store):
            def touch_session(self, session_id_hash, **kwargs):
                self.current_users[kwargs["subject"]]["sessionVersion"] += 1
                raise session_v2.CurrentUserSessionStale(
                    "current user state changed"
                )

        store = ConcurrentVersionBumpStore()
        self.seed_session(store)

        response, _, _ = self.run_v2(
            v2_event(
                "GET",
                "/auth-v2/session/me",
                cookies=[f"{SESSION_COOKIE}=live-session-token"],
            ),
            store=store,
        )

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(response_body(response)["errorCode"], "auth_required")
        self.assertNotIn("account", response_body(response))

    def test_me_rejects_persisted_client_owner_roles_that_are_missing_or_not_exact(self):
        event = v2_event(
            "GET",
            "/auth-v2/session/me",
            cookies=[f"{SESSION_COOKIE}=live-session-token"],
        )
        for roles in ([], ["journal-owner", "unexpected-admin"]):
            with self.subTest(roles=roles):
                store = FakeV2Store()
                record = self.seed_session(store)
                record["roles"] = roles
                store.sessions[hash_text("live-session-token")] = record

                response, _, _ = self.run_v2(event, store=store)

                self.assertEqual(response["statusCode"], 401)
                current_reads = [
                    call for call in store.calls if call[0] == "current_user_get"
                ]
                self.assertEqual(current_reads, [])

    def test_me_revalidates_enabled_subject_and_exact_group_in_cognito(self):
        event = v2_event(
            "GET",
            "/auth-v2/session/me",
            cookies=[f"{SESSION_COOKIE}=live-session-token"],
        )
        cases = (
            (FakeCognito(current_user_groups=[]), 401),
            (
                FakeCognito(
                    current_user_groups=["journal-owner", "unexpected-admin"]
                ),
                401,
            ),
            (FakeCognito(current_user_enabled=False), 401),
            (FakeCognito(current_user_subject="different-subject"), 401),
            (FakeCognito(), 200),
        )
        for cognito, expected_status in cases:
            with self.subTest(expected_status=expected_status, calls=cognito.calls):
                store = FakeV2Store()
                self.seed_session(store)

                response, _, _ = self.run_v2(event, store=store, cognito=cognito)

                self.assertEqual(response["statusCode"], expected_status)
                self.assertEqual(
                    [name for name, _kwargs in cognito.calls],
                    ["admin_get_user"]
                    if cognito.current_user_enabled is False
                    or cognito.current_user_subject != "owner-123"
                    else ["admin_get_user", "admin_list_groups_for_user"],
                )

    def test_me_handles_group_pagination_and_provider_failures_without_touching_session(self):
        event = v2_event(
            "GET",
            "/auth-v2/session/me",
            cookies=[f"{SESSION_COOKIE}=live-session-token"],
        )
        valid_pages = [
            {"Groups": [], "NextToken": "page-2"},
            {"Groups": [{"GroupName": "journal-owner"}]},
        ]
        valid_store = FakeV2Store()
        self.seed_session(valid_store)
        valid, _, valid_cognito = self.run_v2(
            event,
            store=valid_store,
            cognito=FakeCognito(current_group_pages=valid_pages),
        )
        self.assertEqual(valid["statusCode"], 200)
        self.assertEqual(
            [name for name, _kwargs in valid_cognito.calls],
            ["admin_get_user", "admin_list_groups_for_user", "admin_list_groups_for_user"],
        )

        cases = (
            (
                FakeCognito(
                    current_group_pages=[
                        {"Groups": [], "NextToken": "repeat"},
                        {"Groups": [], "NextToken": "repeat"},
                    ]
                ),
                503,
            ),
            (FakeCognito(current_user_error=AwsProviderError("UserNotFoundException")), 401),
            (FakeCognito(current_user_error=AwsProviderError("AccessDeniedException")), 503),
        )
        for cognito, expected_status in cases:
            with self.subTest(expected_status=expected_status):
                store = FakeV2Store()
                self.seed_session(store)
                response, _, _ = self.run_v2(event, store=store, cognito=cognito)

                self.assertEqual(response["statusCode"], expected_status)
                self.assertNotIn("touch_session", [call[0] for call in store.calls])

    def test_qa_session_does_not_depend_on_the_client_owner_cognito_group(self):
        qa_state = current_user_state(account_purpose="qa")
        store = FakeV2Store(users=[qa_state])
        self.seed_session(store, account_purpose="qa")
        cognito = FakeCognito(current_user_groups=[])

        response, _, _ = self.run_v2(
            v2_event(
                "GET",
                "/auth-v2/session/me",
                cookies=[f"{SESSION_COOKIE}=live-session-token"],
            ),
            store=store,
            cognito=cognito,
        )

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(cognito.calls, [])

    def test_me_enforces_idle_and_absolute_expiry_without_extending_absolute_deadline(self):
        store = FakeV2Store()
        original = self.seed_session(store)
        event = v2_event(
            "GET",
            "/auth-v2/session/me",
            cookies=[f"{SESSION_COOKIE}=live-session-token"],
        )
        active, _, _ = self.run_v2(event, store=store, now=NOW)
        self.assertEqual(active["statusCode"], 200)
        touched = store.sessions[hash_text("live-session-token")]
        self.assertEqual(touched["idleExpiresAt"], NOW + SESSION_IDLE_SECONDS)
        self.assertEqual(touched["absoluteExpiresAt"], original["absoluteExpiresAt"])

        idle_store = FakeV2Store()
        self.seed_session(idle_store, idle_expires_at=NOW)
        idle_expired, _, _ = self.run_v2(event, store=idle_store, now=NOW)
        self.assertEqual(idle_expired["statusCode"], 401)

        absolute_store = FakeV2Store()
        self.seed_session(
            absolute_store,
            idle_expires_at=NOW + 1,
            absolute_expires_at=NOW,
        )
        absolute_expired, _, _ = self.run_v2(event, store=absolute_store, now=NOW)
        self.assertEqual(absolute_expired["statusCode"], 401)

    def test_csrf_is_required_and_logout_revokes_only_the_v2_session(self):
        store = FakeV2Store()
        self.seed_session(store)
        base_event = {
            "method": "POST",
            "path": "/auth-v2/session/logout",
            "body": {},
            "cookies": [
                "__Host-zlp_session=legacy-v1-session",
                "zlp_csrf=legacy-v1-csrf",
                f"{SESSION_COOKIE}=live-session-token",
                f"{CSRF_COOKIE}=live-csrf-token",
            ],
        }
        mismatch, _, _ = self.run_v2(
            v2_event(
                base_event["method"],
                base_event["path"],
                base_event["body"],
                cookies=base_event["cookies"],
                headers={"x-zlp-csrf": "wrong-csrf"},
            ),
            store=store,
        )
        self.assertEqual(mismatch["statusCode"], 403)
        self.assertIsNone(store.sessions[hash_text("live-session-token")]["revokedAt"])

        success, _, _ = self.run_v2(
            v2_event(
                base_event["method"],
                base_event["path"],
                base_event["body"],
                cookies=base_event["cookies"],
                headers={"x-zlp-csrf": "live-csrf-token"},
            ),
            store=store,
        )
        self.assertEqual(success["statusCode"], 200)
        self.assertEqual(
            store.sessions[hash_text("live-session-token")]["revokedAt"], NOW
        )
        cleared = response_cookies(success)
        self.assertTrue(cookie_line(cleared, SESSION_COOKIE).endswith("Max-Age=0"))
        self.assertTrue(cookie_line(cleared, CSRF_COOKIE).endswith("Max-Age=0"))
        self.assertFalse(any(cookie.startswith("__Host-zlp_session=") for cookie in cleared))
        self.assertFalse(any(cookie.startswith("zlp_csrf=") for cookie in cleared))

    def test_logout_revoke_failure_is_unavailable_and_does_not_clear_cookies(self):
        class RevokeFailureStore(FakeV2Store):
            def revoke_session(self, session_id_hash, *, now):
                self.calls.append(("revoke_session", session_id_hash, now))
                return False

        store = RevokeFailureStore()
        self.seed_session(store)
        response, _, cognito = self.run_v2(
            v2_event(
                "POST",
                "/auth-v2/session/logout",
                {},
                cookies=[
                    f"{SESSION_COOKIE}=live-session-token",
                    f"{CSRF_COOKIE}=live-csrf-token",
                ],
                headers={"x-zlp-csrf": "live-csrf-token"},
            ),
            store=store,
        )

        self.assertEqual(response["statusCode"], 503)
        self.assertEqual(response_body(response).get("errorCode"), "auth_unavailable")
        self.assertEqual(response_cookies(response), [])
        self.assertIsNone(store.sessions[hash_text("live-session-token")]["revokedAt"])
        self.assertEqual(
            [name for name, _kwargs in cognito.calls],
            ["admin_get_user", "admin_list_groups_for_user"],
        )

    def test_v1_cookie_constants_and_handler_coexist_without_v2_collision(self):
        self.assertEqual(auth_admin.SESSION_COOKIE_NAME, "__Host-zlp_session")
        self.assertEqual(auth_admin.CHALLENGE_COOKIE_NAME, "__Host-zlp_challenge")
        self.assertEqual(auth_admin.MFA_ENROLLMENT_COOKIE_NAME, "__Host-zlp_mfa_enroll")
        self.assertEqual(auth_admin.CSRF_COOKIE_NAME, "zlp_csrf")
        self.assertEqual(auth_admin.CHALLENGE_CSRF_COOKIE_NAME, "zlp_challenge_csrf")
        self.assertEqual(auth_admin.MFA_ENROLLMENT_CSRF_COOKIE_NAME, "zlp_mfa_enroll_csrf")
        self.assertIsNot(session_v2.lambda_handler, auth_admin.lambda_handler)
        self.assertTrue(
            {
                SESSION_COOKIE,
                CHALLENGE_COOKIE,
                ENROLLMENT_COOKIE,
                CSRF_COOKIE,
                CHALLENGE_CSRF_COOKIE,
                ENROLLMENT_CSRF_COOKIE,
            }.isdisjoint(
                {
                    auth_admin.SESSION_COOKIE_NAME,
                    auth_admin.CHALLENGE_COOKIE_NAME,
                    auth_admin.MFA_ENROLLMENT_COOKIE_NAME,
                    auth_admin.CSRF_COOKIE_NAME,
                    auth_admin.CHALLENGE_CSRF_COOKIE_NAME,
                    auth_admin.MFA_ENROLLMENT_CSRF_COOKIE_NAME,
                }
            )
        )


class TokenVerificationContractTests(unittest.TestCase):
    def test_cognito_id_token_decode_requires_authorization_claims(self):
        decode_calls = []
        issuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_THNTEST"
        claims = {
            "sub": "owner-123",
            "token_use": "id",
            "exp": NOW + 300,
            "iss": issuer,
            "iat": NOW - 60,
            "aud": "thnv2client",
        }

        class FakeJwkClient:
            def __init__(self, url):
                self.url = url

            def get_signing_key_from_jwt(self, token):
                self.token = token
                return types.SimpleNamespace(key="public-key-sentinel")

        fake_jwt = types.ModuleType("jwt")
        fake_jwt.PyJWKClient = FakeJwkClient

        def fake_decode(*args, **kwargs):
            decode_calls.append((copy.deepcopy(args), copy.deepcopy(kwargs)))
            return copy.deepcopy(claims)

        fake_jwt.decode = fake_decode
        with (
            patch.dict(
                os.environ,
                {
                    "THN_AUTH_V2_COGNITO_REGION": "us-east-1",
                    "THN_AUTH_V2_COGNITO_USER_POOL_ID": "us-east-1_THNTEST",
                    "THN_AUTH_V2_COGNITO_CLIENT_ID": "thnv2client",
                },
                clear=False,
            ),
            patch.dict(sys.modules, {"jwt": fake_jwt}),
        ):
            verified = session_v2._verify_id_token("signed-id-token")

        self.assertEqual(verified, claims)
        self.assertEqual(len(decode_calls), 1)
        args, kwargs = decode_calls[0]
        self.assertEqual(args[:2], ("signed-id-token", "public-key-sentinel"))
        self.assertEqual(kwargs["algorithms"], ["RS256"])
        self.assertEqual(kwargs["audience"], "thnv2client")
        self.assertEqual(kwargs["issuer"], issuer)
        self.assertIn("options", kwargs)
        self.assertEqual(
            set(kwargs["options"].get("require") or []),
            {"exp", "iat", "iss", "aud", "sub", "token_use"},
        )
        self.assertIs(kwargs["options"].get("strict_aud"), True)


if __name__ == "__main__":
    unittest.main()
