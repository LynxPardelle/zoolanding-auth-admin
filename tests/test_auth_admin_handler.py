import base64
import json
import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlparse

import lambda_function as auth_admin


def encoded_config(**profile_overrides):
    profile = {
        "enabled": True,
        "environment": "test",
        "domain": "zoositioweb.com.mx",
        "authProfileId": "staff",
        "provider": "cognito",
        "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
        "userPoolId": "us-east-1_pool",
        "clientId": "public-client-id",
        "audiences": ["public-client-id"],
        "tenantId": "zoosite",
        "tenantClaim": "custom:tenant_id",
        "environmentClaim": "custom:zoolanding_env",
        "groupClaim": "cognito:groups",
        "allowedGroups": ["zoosite-client", "zoosite-admin"],
        "adminGroups": ["zoosite-admin"],
        "defaultUserStatus": "pending",
        "adminGroupsAutoApproved": True,
        "manageableGroups": ["zoosite-client", "zoosite-admin"],
        "customAuth": {
            "signin": {"enabled": True}
        },
    }
    profile.update(profile_overrides)
    raw = json.dumps({"version": 1, "profiles": [profile]}, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def http_event(method, path, body=None, headers=None, cookies=None, auth_context=True):
    request_headers = {}
    if auth_context:
        request_headers.update({
            "x-zlp-domain": "zoositioweb.com.mx",
            "x-zlp-auth-profile-id": "staff",
        })
    request_headers.update(headers or {})
    return {
        "version": "2.0",
        "routeKey": f"{method} {path}",
        "rawPath": path,
        "headers": request_headers,
        "cookies": cookies or [],
        "requestContext": {
            "http": {
                "method": method,
                "path": path,
            },
            "requestId": "request-1",
        },
        "body": json.dumps(body) if body is not None else None,
    }


def body(response):
    return json.loads(response.get("body") or "{}")


def admin_claims():
    return {
        "sub": "admin-sub",
        "email": "admin@example.test",
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
        "aud": "public-client-id",
        "token_use": "id",
        "custom:tenant_id": "zoosite",
        "custom:zoolanding_env": "test",
        "cognito:groups": ["zoosite-admin"],
        "exp": 4102444800,
    }


class FakeCognito:
    def __init__(
        self,
        groups_by_username=None,
        auth_response=None,
        respond_response=None,
        respond_error=None,
        associate_error=None,
        verify_error=None,
        preference_error=None,
        mfa_settings_by_username=None,
        admin_get_user_error=None,
    ):
        self.calls = []
        self.groups_by_username = groups_by_username or {}
        self.auth_response = auth_response
        self.respond_response = respond_response
        self.respond_error = respond_error
        self.associate_error = associate_error
        self.verify_error = verify_error
        self.preference_error = preference_error
        self.mfa_settings_by_username = mfa_settings_by_username or {}
        self.admin_get_user_error = admin_get_user_error

    def initiate_auth(self, **kwargs):
        self.calls.append(("initiate_auth", kwargs))
        if self.auth_response is not None:
            return self.auth_response
        return {
            "AuthenticationResult": {
                "IdToken": "valid-id-token"
            }
        }

    def respond_to_auth_challenge(self, **kwargs):
        self.calls.append(("respond_to_auth_challenge", kwargs))
        if self.respond_error:
            raise self.respond_error
        if self.respond_response is not None:
            return self.respond_response
        return {
            "AuthenticationResult": {
                "IdToken": "valid-id-token"
            }
        }

    def associate_software_token(self, **kwargs):
        self.calls.append(("associate_software_token", kwargs))
        if self.associate_error:
            raise self.associate_error
        return {
            "SecretCode": "ABCDEFGHIJKLMNOP",
            "Session": "associated-session",
        }

    def verify_software_token(self, **kwargs):
        self.calls.append(("verify_software_token", kwargs))
        if self.verify_error:
            raise self.verify_error
        return {
            "Status": "SUCCESS",
            "Session": "verified-session",
        }

    def set_user_mfa_preference(self, **kwargs):
        self.calls.append(("set_user_mfa_preference", kwargs))
        if self.preference_error:
            raise self.preference_error
        return {}

    def admin_get_user(self, **kwargs):
        self.calls.append(("admin_get_user", kwargs))
        if self.admin_get_user_error:
            raise self.admin_get_user_error
        return self.mfa_settings_by_username.get(kwargs["Username"], {
            "UserMFASettingList": [],
            "PreferredMfaSetting": "",
        })

    def admin_list_groups_for_user(self, **kwargs):
        self.calls.append(("admin_list_groups_for_user", kwargs))
        groups = self.groups_by_username.get(kwargs["Username"], [])
        return {"Groups": [{"GroupName": group} for group in groups]}

    def admin_add_user_to_group(self, **kwargs):
        self.calls.append(("admin_add_user_to_group", kwargs))
        return {}

    def admin_remove_user_from_group(self, **kwargs):
        self.calls.append(("admin_remove_user_from_group", kwargs))
        return {}

    def admin_disable_user(self, **kwargs):
        self.calls.append(("admin_disable_user", kwargs))
        return {}

    def admin_enable_user(self, **kwargs):
        self.calls.append(("admin_enable_user", kwargs))
        return {}


class FakeDynamo:
    def __init__(self):
        self.sessions = {}
        self.users = {}
        self.audit = []
        self.calls = []

    def put_session(self, item):
        self.calls.append(("put_session", item))
        self.sessions[item["sessionIdHash"]] = dict(item)

    def get_session(self, session_id_hash):
        self.calls.append(("get_session", session_id_hash))
        item = self.sessions.get(session_id_hash)
        return dict(item) if item else None

    def revoke_session(self, session_id_hash, revoked_at):
        self.calls.append(("revoke_session", session_id_hash, revoked_at))
        if session_id_hash in self.sessions:
            self.sessions[session_id_hash]["revokedAt"] = revoked_at

    def put_user_if_absent(self, key, item):
        self.calls.append(("put_user_if_absent", key, item))
        self.users.setdefault(key, dict(item))
        return dict(self.users[key])

    def get_user(self, key):
        self.calls.append(("get_user", key))
        item = self.users.get(key)
        return dict(item) if item else None

    def list_users(self, tenant_profile_key):
        self.calls.append(("list_users", tenant_profile_key))
        return [
            dict(item)
            for key, item in self.users.items()
            if key[0] == tenant_profile_key
        ]

    def update_user(self, key, updates):
        self.calls.append(("update_user", key, updates))
        current = dict(self.users.get(key, {}))
        current.update(updates)
        self.users[key] = current
        return dict(current)

    def write_audit(self, item):
        self.calls.append(("write_audit", item))
        self.audit.append(dict(item))


class AuthAdminHandlerTests(unittest.TestCase):
    def run_with_fakes(self, event, *, claims=None, fake_dynamo=None, fake_cognito=None, env=None, random_values=None):
        fake_dynamo = fake_dynamo or FakeDynamo()
        fake_cognito = fake_cognito or FakeCognito()
        claims = claims or {
            "sub": "client-sub",
            "email": "client@example.test",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            "aud": "public-client-id",
            "token_use": "id",
            "custom:tenant_id": "zoosite",
            "custom:zoolanding_env": "test",
            "cognito:groups": ["zoosite-client"],
            "exp": 4102444800,
        }
        environment = {
            "AUTH_ADMIN_CONFIG_JSON_BASE64": encoded_config(),
            "AUTH_ADMIN_ENVIRONMENT": "test",
            "LOG_LEVEL": "ERROR",
        }
        environment.update(env or {})
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(auth_admin, "_cognito_client", return_value=fake_cognito), \
                patch.object(auth_admin, "_session_store", return_value=fake_dynamo), \
                patch.object(auth_admin, "_verify_jwt", return_value=claims), \
                patch.object(auth_admin, "_random_urlsafe", side_effect=random_values or ["session-value", "csrf-value"]), \
                patch.object(auth_admin, "_now_epoch", return_value=1_800_000_000):
            response = auth_admin.lambda_handler(event, object())
        return response, fake_dynamo, fake_cognito

    def sign_in(self, *, claims=None, env=None):
        response, fake_dynamo, fake_cognito = self.run_with_fakes(http_event("POST", "/auth/session/signin", {
            "domain": "zoositioweb.com.mx",
            "authProfileId": "staff",
            "email": "client@example.test",
            "password": "ValidPass123!",
            "language": "es",
        }), claims=claims, env=env)
        self.assertEqual(response["statusCode"], 200)
        cookies = response.get("cookies") or []
        session_cookie = next(cookie for cookie in cookies if cookie.startswith("__Host-zlp_session="))
        csrf_cookie = next(cookie for cookie in cookies if not cookie.startswith("__Host-zlp_session="))
        session_value = session_cookie.split(";", 1)[0].split("=", 1)[1]
        csrf_value = csrf_cookie.split(";", 1)[0].split("=", 1)[1]
        return response, fake_dynamo, fake_cognito, session_value, csrf_value

    def test_config_rejects_secret_like_keys(self):
        with patch.dict(os.environ, {
            "AUTH_ADMIN_CONFIG_JSON_BASE64": encoded_config(clientSecret="blocked"),
        }, clear=True):
            with self.assertRaises(auth_admin.AuthAdminConfigError):
                auth_admin.load_config()

    def test_signin_creates_private_session_and_safe_cookies(self):
        response, fake_dynamo, fake_cognito, _, _ = self.sign_in()

        response_body = body(response)
        self.assertEqual(response_body["status"], "signed-in")
        self.assertEqual(response_body["session"]["profile"]["subject"], "client-sub")
        self.assertEqual(response_body["session"]["profile"]["roles"], ["zoosite-client"])
        self.assertEqual(response_body["session"]["profile"]["approvalStatus"], "pending")
        self.assertNotIn("valid-id-token", json.dumps(response_body))
        self.assertEqual([call[0] for call in fake_cognito.calls], ["initiate_auth"])
        self.assertEqual(len(fake_dynamo.sessions), 1)

        cookies = "\n".join(response.get("cookies") or [])
        self.assertIn("__Host-zlp_session=session-value; HttpOnly; Secure; SameSite=Lax; Path=/", cookies)
        self.assertIn("zlp_csrf=csrf-value; Secure; SameSite=Lax; Path=/", cookies)

    def test_signin_challenge_stores_cognito_session_server_side(self):
        fake_cognito = FakeCognito(auth_response={
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "ChallengeParameters": {"USER_ID_FOR_SRP": "client-cognito-username"},
            "Session": "raw-cognito-session",
        })

        response, fake_dynamo, _ = self.run_with_fakes(http_event("POST", "/auth/session/signin", {
            "domain": "zoositioweb.com.mx",
            "authProfileId": "staff",
            "email": "client@example.test",
            "password": "ValidPass123!",
        }), fake_cognito=fake_cognito)

        response_body = body(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response_body["status"], "challenge-required")
        self.assertEqual(response_body["challengeName"], "SOFTWARE_TOKEN_MFA")
        self.assertIn("__Host-zlp_challenge=session-value; HttpOnly; Secure; SameSite=Lax; Path=/", "\n".join(response.get("cookies") or []))
        self.assertIn("zlp_challenge_csrf=csrf-value; Secure; SameSite=Lax; Path=/", "\n".join(response.get("cookies") or []))
        self.assertNotIn("raw-cognito-session", json.dumps(response_body))
        self.assertEqual(len(fake_dynamo.sessions), 1)
        challenge_record = next(iter(fake_dynamo.sessions.values()))
        self.assertEqual(challenge_record["recordType"], "authChallenge")
        self.assertEqual(challenge_record["cognitoSession"], "raw-cognito-session")
        self.assertEqual(challenge_record["challengeCsrfHash"], auth_admin._sha256("csrf-value"))

    def test_software_token_mfa_challenge_creates_private_session(self):
        challenge_response = {
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "ChallengeParameters": {"USER_ID_FOR_SRP": "client-cognito-username"},
            "Session": "raw-cognito-session",
        }
        _, fake_dynamo, _ = self.run_with_fakes(
            http_event("POST", "/auth/session/signin", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "email": "client@example.test",
                "password": "ValidPass123!",
            }),
            fake_cognito=FakeCognito(auth_response=challenge_response),
        )

        response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/challenge/respond", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "code": "123456",
            }, headers={"x-zlp-csrf": "csrf-value"}, cookies=["__Host-zlp_challenge=session-value", "zlp_challenge_csrf=csrf-value"]),
            fake_dynamo=fake_dynamo,
        )

        response_body = body(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response_body["status"], "signed-in")
        self.assertIn(("respond_to_auth_challenge", {
            "ClientId": "public-client-id",
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "Session": "raw-cognito-session",
            "ChallengeResponses": {
                "USERNAME": "client-cognito-username",
                "SOFTWARE_TOKEN_MFA_CODE": "123456",
            },
            "ClientMetadata": {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "environment": "test",
            },
        }), fake_cognito.calls)
        self.assertNotIn("raw-cognito-session", json.dumps(response_body))
        self.assertIn("__Host-zlp_challenge=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0", "\n".join(response.get("cookies") or []))
        self.assertIn("zlp_challenge_csrf=; Secure; SameSite=Lax; Path=/; Max-Age=0", "\n".join(response.get("cookies") or []))

    def test_software_token_mfa_challenge_requires_challenge_csrf(self):
        challenge_response = {
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "ChallengeParameters": {"USER_ID_FOR_SRP": "client-cognito-username"},
            "Session": "raw-cognito-session",
        }
        _, fake_dynamo, _ = self.run_with_fakes(
            http_event("POST", "/auth/session/signin", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "email": "client@example.test",
                "password": "ValidPass123!",
            }),
            fake_cognito=FakeCognito(auth_response=challenge_response),
        )

        response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/challenge/respond", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "code": "123456",
            }, cookies=["__Host-zlp_challenge=session-value", "zlp_challenge_csrf=wrong-value"]),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(body(response)["error"], "CSRF validation failed")
        self.assertEqual(fake_cognito.calls, [])

    def test_software_token_mfa_cognito_error_returns_controlled_unauthorized(self):
        challenge_response = {
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "ChallengeParameters": {"USER_ID_FOR_SRP": "client-cognito-username"},
            "Session": "raw-cognito-session",
        }
        _, fake_dynamo, _ = self.run_with_fakes(
            http_event("POST", "/auth/session/signin", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "email": "client@example.test",
                "password": "ValidPass123!",
            }),
            fake_cognito=FakeCognito(auth_response=challenge_response),
        )

        response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/challenge/respond", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "code": "123456",
            }, headers={"x-zlp-csrf": "csrf-value"}, cookies=["__Host-zlp_challenge=session-value", "zlp_challenge_csrf=csrf-value"]),
            fake_dynamo=fake_dynamo,
            fake_cognito=FakeCognito(respond_error=RuntimeError("expired-cognito-session")),
        )

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(body(response)["error"], "Authentication challenge failed")
        self.assertEqual([call[0] for call in fake_cognito.calls], ["respond_to_auth_challenge"])

    def test_mfa_challenge_rejects_unsupported_next_challenge(self):
        challenge_response = {
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "ChallengeParameters": {"USER_ID_FOR_SRP": "client-cognito-username"},
            "Session": "raw-cognito-session",
        }
        _, fake_dynamo, _ = self.run_with_fakes(
            http_event("POST", "/auth/session/signin", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "email": "client@example.test",
                "password": "ValidPass123!",
            }),
            fake_cognito=FakeCognito(auth_response=challenge_response),
        )

        response, _, _ = self.run_with_fakes(
            http_event("POST", "/auth/session/challenge/respond", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "code": "123456",
            }, headers={"x-zlp-csrf": "csrf-value"}, cookies=["__Host-zlp_challenge=session-value", "zlp_challenge_csrf=csrf-value"]),
            fake_dynamo=fake_dynamo,
            fake_cognito=FakeCognito(respond_response={
                "ChallengeName": "CUSTOM_CHALLENGE",
                "Session": "next-session",
            }),
        )

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(body(response)["error"], "Authentication challenge failed")

    def test_mfa_setup_challenge_associates_and_verifies_totp_without_exposing_session(self):
        challenge_response = {
            "ChallengeName": "MFA_SETUP",
            "ChallengeParameters": {"USER_ID_FOR_SRP": "client-cognito-username", "MFAS_CAN_SETUP": '["SOFTWARE_TOKEN_MFA"]'},
            "Session": "setup-cognito-session",
        }
        _, fake_dynamo, _ = self.run_with_fakes(
            http_event("POST", "/auth/session/signin", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "email": "client@example.test",
                "password": "ValidPass123!",
            }),
            fake_cognito=FakeCognito(auth_response=challenge_response),
        )

        setup_response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/mfa/setup", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
            }, headers={"x-zlp-csrf": "csrf-value"}, cookies=["__Host-zlp_challenge=session-value", "zlp_challenge_csrf=csrf-value"]),
            fake_dynamo=fake_dynamo,
        )

        setup_body = body(setup_response)
        self.assertEqual(setup_response["statusCode"], 200)
        self.assertEqual(setup_body["status"], "mfa-setup-ready")
        self.assertEqual(setup_body["setup"]["sharedSecret"], "ABCDEFGHIJKLMNOP")
        self.assertIn("otpauth://totp/", setup_body["setup"]["otpauthUri"])
        self.assertNotIn("setup-cognito-session", json.dumps(setup_body))
        self.assertIn(("associate_software_token", {
            "Session": "setup-cognito-session",
        }), fake_cognito.calls)

        verify_response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/mfa/verify", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "code": "654321",
            }, headers={"x-zlp-csrf": "csrf-value"}, cookies=["__Host-zlp_challenge=session-value", "zlp_challenge_csrf=csrf-value"]),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
        )

        verify_body = body(verify_response)
        self.assertEqual(verify_response["statusCode"], 200)
        self.assertEqual(verify_body["status"], "signed-in")
        self.assertIn(("verify_software_token", {
            "Session": "associated-session",
            "UserCode": "654321",
            "FriendlyDeviceName": "zoositioweb.com.mx authenticator",
        }), fake_cognito.calls)
        self.assertIn(("respond_to_auth_challenge", {
            "ClientId": "public-client-id",
            "ChallengeName": "MFA_SETUP",
            "Session": "verified-session",
            "ChallengeResponses": {
                "USERNAME": "client-cognito-username",
            },
            "ClientMetadata": {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "environment": "test",
            },
        }), fake_cognito.calls)
        self.assertNotIn("associated-session", json.dumps(verify_body))

    def test_authenticated_user_can_enroll_totp_without_browser_tokens(self):
        _, fake_dynamo, _, session_value, csrf_value = self.sign_in()
        fake_cognito = FakeCognito(auth_response={
            "AuthenticationResult": {
                "IdToken": "reauth-id-token",
                "AccessToken": "server-only-access-token",
                "RefreshToken": "server-only-refresh-token",
            }
        })

        setup_response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/mfa/enroll/start", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "password": "ValidPass123!",
                "language": "es",
            }, headers={"x-zlp-csrf": csrf_value}, cookies=[f"__Host-zlp_session={session_value}", f"zlp_csrf={csrf_value}"]),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
            random_values=["mfa-enroll-value", "mfa-enroll-csrf"],
        )

        setup_body = body(setup_response)
        self.assertEqual(setup_response["statusCode"], 200)
        self.assertEqual(setup_body["status"], "mfa-enrollment-ready")
        self.assertEqual(setup_body["setup"]["sharedSecret"], "ABCDEFGHIJKLMNOP")
        self.assertIn("otpauth://totp/", setup_body["setup"]["otpauthUri"])
        self.assertNotIn("server-only-access-token", json.dumps(setup_body))
        self.assertNotIn("server-only-refresh-token", json.dumps(setup_body))
        self.assertIn(("associate_software_token", {
            "AccessToken": "server-only-access-token",
        }), fake_cognito.calls)
        setup_cookies = "\n".join(setup_response.get("cookies") or [])
        self.assertIn("__Host-zlp_mfa_enroll=mfa-enroll-value; HttpOnly; Secure; SameSite=Lax; Path=/", setup_cookies)
        self.assertIn("zlp_mfa_enroll_csrf=mfa-enroll-csrf; Secure; SameSite=Lax; Path=/", setup_cookies)
        enrollment_record = fake_dynamo.sessions[auth_admin._sha256("mfa-enroll-value")]
        self.assertEqual(enrollment_record["recordType"], "authMfaEnrollment")
        self.assertEqual(enrollment_record["cognitoAccessToken"], "server-only-access-token")
        self.assertEqual(enrollment_record["subject"], "client-sub")

        verify_response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/mfa/enroll/verify", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "code": "123456",
            }, headers={"x-zlp-csrf": "mfa-enroll-csrf"}, cookies=[
                f"__Host-zlp_session={session_value}",
                f"zlp_csrf={csrf_value}",
                "__Host-zlp_mfa_enroll=mfa-enroll-value",
                "zlp_mfa_enroll_csrf=mfa-enroll-csrf",
            ]),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
            random_values=[],
        )

        verify_body = body(verify_response)
        self.assertEqual(verify_response["statusCode"], 200)
        self.assertEqual(verify_body["status"], "mfa-enabled")
        self.assertEqual(verify_body["account"]["subject"], "client-sub")
        self.assertIn(("verify_software_token", {
            "AccessToken": "server-only-access-token",
            "UserCode": "123456",
            "FriendlyDeviceName": "zoositioweb.com.mx authenticator",
        }), fake_cognito.calls)
        self.assertIn(("set_user_mfa_preference", {
            "AccessToken": "server-only-access-token",
            "SoftwareTokenMfaSettings": {
                "Enabled": True,
                "PreferredMfa": True,
            },
        }), fake_cognito.calls)
        self.assertNotIn("server-only-access-token", json.dumps(verify_body))
        self.assertNotIn("server-only-refresh-token", json.dumps(verify_body))
        cleared_cookies = "\n".join(verify_response.get("cookies") or [])
        self.assertIn("__Host-zlp_mfa_enroll=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0", cleared_cookies)
        self.assertIn("zlp_mfa_enroll_csrf=; Secure; SameSite=Lax; Path=/; Max-Age=0", cleared_cookies)
        self.assertTrue(fake_dynamo.sessions[auth_admin._sha256("mfa-enroll-value")]["revokedAt"])

    def test_totp_setup_uses_profile_configurable_issuer_label_and_device_name(self):
        env = {
            "AUTH_ADMIN_CONFIG_JSON_BASE64": encoded_config(mfa={
                "mode": "optional",
                "totp": {
                    "enabled": True,
                    "issuer": "zoositioweb",
                    "accountLabelTemplate": "{email}",
                    "friendlyDeviceName": "zoositioweb acceso",
                },
            })
        }
        _, fake_dynamo, _, session_value, csrf_value = self.sign_in(env=env)
        fake_cognito = FakeCognito(auth_response={
            "AuthenticationResult": {
                "IdToken": "reauth-id-token",
                "AccessToken": "server-only-access-token",
            }
        })

        setup_response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/mfa/enroll/start", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "password": "ValidPass123!",
                "language": "es",
            }, headers={"x-zlp-csrf": csrf_value}, cookies=[
                f"__Host-zlp_session={session_value}",
                f"zlp_csrf={csrf_value}",
            ]),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
            env=env,
            random_values=["mfa-enroll-value", "mfa-enroll-csrf"],
        )

        setup_body = body(setup_response)
        otpauth = urlparse(setup_body["setup"]["otpauthUri"])
        self.assertEqual(unquote(otpauth.path.lstrip("/")), "zoositioweb:client@example.test")
        self.assertEqual(parse_qs(otpauth.query)["issuer"], ["zoositioweb"])

        verify_response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/mfa/enroll/verify", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "code": "123456",
            }, headers={"x-zlp-csrf": "mfa-enroll-csrf"}, cookies=[
                f"__Host-zlp_session={session_value}",
                f"zlp_csrf={csrf_value}",
                "__Host-zlp_mfa_enroll=mfa-enroll-value",
                "zlp_mfa_enroll_csrf=mfa-enroll-csrf",
            ]),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
            env=env,
        )

        self.assertEqual(verify_response["statusCode"], 200)
        self.assertIn(("verify_software_token", {
            "AccessToken": "server-only-access-token",
            "UserCode": "123456",
            "FriendlyDeviceName": "zoositioweb acceso",
        }), fake_cognito.calls)

    def test_authenticated_user_can_disable_totp_after_password_and_code_reauth(self):
        _, fake_dynamo, _, session_value, csrf_value = self.sign_in()
        fake_cognito = FakeCognito(
            auth_response={
                "ChallengeName": "SOFTWARE_TOKEN_MFA",
                "Session": "disable-mfa-session",
                "ChallengeParameters": {"USER_ID_FOR_SRP": "client-cognito-username"},
            },
            respond_response={
                "AuthenticationResult": {
                    "IdToken": "disable-id-token",
                    "AccessToken": "disable-access-token",
                }
            },
        )

        response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/mfa/disable", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "password": "ValidPass123!",
                "code": "123456",
                "language": "es",
            }, headers={"x-zlp-csrf": csrf_value}, cookies=[
                f"__Host-zlp_session={session_value}",
                f"zlp_csrf={csrf_value}",
            ]),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
        )

        response_body = body(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response_body["status"], "mfa-disabled")
        self.assertIn(("respond_to_auth_challenge", {
            "ClientId": "public-client-id",
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "Session": "disable-mfa-session",
            "ChallengeResponses": {
                "USERNAME": "client-cognito-username",
                "SOFTWARE_TOKEN_MFA_CODE": "123456",
            },
            "ClientMetadata": {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "environment": "test",
                "language": "es",
            },
        }), fake_cognito.calls)
        self.assertIn(("set_user_mfa_preference", {
            "AccessToken": "disable-access-token",
            "SoftwareTokenMfaSettings": {
                "Enabled": False,
                "PreferredMfa": False,
            },
        }), fake_cognito.calls)
        self.assertNotIn("disable-access-token", json.dumps(response_body))

    def test_disable_totp_requires_active_session_csrf_password_and_code(self):
        _, fake_dynamo, _, session_value, csrf_value = self.sign_in()

        response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/mfa/disable", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "password": "ValidPass123!",
                "code": "123456",
            }, cookies=[f"__Host-zlp_session={session_value}", f"zlp_csrf={csrf_value}"]),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(body(response)["error"], "CSRF validation failed")
        self.assertEqual(fake_cognito.calls, [])

    def test_voluntary_mfa_enrollment_requires_active_session_csrf_and_password(self):
        _, fake_dynamo, _, session_value, csrf_value = self.sign_in()

        response, _, fake_cognito = self.run_with_fakes(
            http_event("POST", "/auth/session/mfa/enroll/start", {
                "domain": "zoositioweb.com.mx",
                "authProfileId": "staff",
                "password": "ValidPass123!",
            }, cookies=[f"__Host-zlp_session={session_value}", f"zlp_csrf={csrf_value}"]),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(body(response)["error"], "CSRF validation failed")
        self.assertEqual(fake_cognito.calls, [])

    def test_me_returns_sanitized_account_for_pending_user(self):
        _, fake_dynamo, _, session_value, _ = self.sign_in()

        response, _, _ = self.run_with_fakes(
            http_event("GET", "/auth/session/me", cookies=[f"__Host-zlp_session={session_value}"]),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 200)
        account = body(response)["account"]
        self.assertEqual(account["subject"], "client-sub")
        self.assertEqual(account["approvalStatus"], "pending")
        self.assertEqual(account["roles"], ["zoosite-client"])
        self.assertNotIn("sessionIdHash", json.dumps(account))
        self.assertNotIn("tenantId", json.dumps(account))
        self.assertEqual(account["mfa"], {
            "status": "disabled",
            "softwareTokenEnabled": False,
            "methods": [],
            "preferredMethod": "",
        })

    def test_me_returns_public_software_token_mfa_state(self):
        _, fake_dynamo, _, session_value, _ = self.sign_in()
        fake_cognito = FakeCognito(mfa_settings_by_username={
            "client@example.test": {
                "UserMFASettingList": ["SOFTWARE_TOKEN_MFA"],
                "PreferredMfaSetting": "SOFTWARE_TOKEN_MFA",
            }
        })

        response, _, fake_cognito = self.run_with_fakes(
            http_event("GET", "/auth/session/me", cookies=[f"__Host-zlp_session={session_value}"]),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
        )

        self.assertEqual(response["statusCode"], 200)
        account = body(response)["account"]
        self.assertEqual(account["mfa"], {
            "status": "enabled",
            "softwareTokenEnabled": True,
            "methods": ["SOFTWARE_TOKEN_MFA"],
            "preferredMethod": "SOFTWARE_TOKEN_MFA",
        })
        self.assertIn(("admin_get_user", {
            "UserPoolId": "us-east-1_pool",
            "Username": "client@example.test",
        }), fake_cognito.calls)
        self.assertNotIn("SecretCode", json.dumps(account))

    def test_me_returns_unknown_mfa_state_when_cognito_state_read_fails(self):
        _, fake_dynamo, _, session_value, _ = self.sign_in()
        fake_cognito = FakeCognito(admin_get_user_error=RuntimeError("cognito-down"))

        response, _, _ = self.run_with_fakes(
            http_event("GET", "/auth/session/me", cookies=[f"__Host-zlp_session={session_value}"]),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
        )

        self.assertEqual(response["statusCode"], 200)
        account = body(response)["account"]
        self.assertEqual(account["mfa"], {
            "status": "unknown",
            "softwareTokenEnabled": None,
            "methods": [],
            "preferredMethod": "",
        })
        self.assertNotIn("SecretCode", json.dumps(account))

    def test_session_request_requires_matching_draft_context(self):
        _, fake_dynamo, _, session_value, _ = self.sign_in()

        response, _, _ = self.run_with_fakes(
            http_event(
                "GET",
                "/auth/session/me",
                headers={"x-zlp-domain": "otherdraft.example"},
                cookies=[f"__Host-zlp_session={session_value}"],
            ),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 401)

    def test_session_request_requires_matching_auth_profile_id(self):
        _, fake_dynamo, _, session_value, _ = self.sign_in()

        response, _, _ = self.run_with_fakes(
            http_event(
                "GET",
                "/auth/session/me",
                headers={"x-zlp-auth-profile-id": "other-profile"},
                cookies=[f"__Host-zlp_session={session_value}"],
            ),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 401)

    def test_session_rejects_revoked_expired_and_version_mismatch(self):
        _, fake_dynamo, _, session_value, _ = self.sign_in(claims=admin_claims())
        tenant_key = "zoositioweb.com.mx#staff#test"
        session_hash = auth_admin._sha256(session_value)

        fake_dynamo.sessions[session_hash]["revokedAt"] = 1_800_000_000
        revoked_response, _, _ = self.run_with_fakes(
            http_event("GET", "/auth/session/me", cookies=[f"__Host-zlp_session={session_value}"]),
            fake_dynamo=fake_dynamo,
        )
        self.assertEqual(revoked_response["statusCode"], 401)

        fake_dynamo.sessions[session_hash]["revokedAt"] = None
        fake_dynamo.sessions[session_hash]["expiresAt"] = 1_800_000_000
        expired_response, _, _ = self.run_with_fakes(
            http_event("GET", "/auth/session/me", cookies=[f"__Host-zlp_session={session_value}"]),
            fake_dynamo=fake_dynamo,
        )
        self.assertEqual(expired_response["statusCode"], 401)

        fake_dynamo.sessions[session_hash]["expiresAt"] = 1_800_003_600
        fake_dynamo.users[(tenant_key, "USER#admin-sub")]["sessionVersion"] = 2
        version_response, _, _ = self.run_with_fakes(
            http_event("GET", "/auth/session/me", cookies=[f"__Host-zlp_session={session_value}"]),
            fake_dynamo=fake_dynamo,
        )
        self.assertEqual(version_response["statusCode"], 401)

    def test_admin_users_requires_approved_admin(self):
        _, fake_dynamo, _, session_value, _ = self.sign_in()

        response, _, _ = self.run_with_fakes(
            http_event("GET", "/auth/admin/users", cookies=[f"__Host-zlp_session={session_value}"]),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(body(response)["error"], "Admin access required")

    def test_approved_admin_can_list_users(self):
        _, fake_dynamo, _, session_value, _ = self.sign_in(claims=admin_claims())
        tenant_key = "zoositioweb.com.mx#staff#test"
        fake_dynamo.users[(tenant_key, "USER#client-sub")] = {
            "tenantProfileKey": tenant_key,
            "subject": "client-sub",
            "email": "client@example.test",
            "roles": ["zoosite-client"],
            "approvalStatus": "pending",
            "enabled": True,
        }

        response, _, _ = self.run_with_fakes(
            http_event("GET", "/auth/admin/users", cookies=[f"__Host-zlp_session={session_value}"]),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 200)
        users = body(response)["users"]
        self.assertEqual([user["subject"] for user in users], ["admin-sub", "client-sub"])
        self.assertNotIn("emailHash", json.dumps(users))

    def test_existing_admin_session_is_rejected_after_admin_is_suspended(self):
        _, fake_dynamo, _, session_value, _ = self.sign_in(claims=admin_claims())
        tenant_key = "zoositioweb.com.mx#staff#test"
        fake_dynamo.users[(tenant_key, "USER#admin-sub")].update({
            "approvalStatus": "suspended",
            "enabled": False,
        })

        response, _, _ = self.run_with_fakes(
            http_event("GET", "/auth/admin/users", cookies=[f"__Host-zlp_session={session_value}"]),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 403)

    def test_existing_admin_session_is_rejected_after_admin_group_removed(self):
        admin_claims = {
            "sub": "admin-sub",
            "email": "admin@example.test",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            "aud": "public-client-id",
            "token_use": "id",
            "custom:tenant_id": "zoosite",
            "custom:zoolanding_env": "test",
            "cognito:groups": ["zoosite-admin"],
            "exp": 4102444800,
        }
        _, fake_dynamo, _, session_value, _ = self.sign_in(claims=admin_claims)
        tenant_key = "zoositioweb.com.mx#staff#test"
        fake_dynamo.users[(tenant_key, "USER#admin-sub")].update({
            "roles": ["zoosite-client"],
            "approvalStatus": "approved",
            "enabled": True,
        })

        response, _, _ = self.run_with_fakes(
            http_event("GET", "/auth/admin/users", cookies=[f"__Host-zlp_session={session_value}"]),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 403)

    def test_approve_user_requires_csrf_and_blocks_self_approval(self):
        _, fake_dynamo, _, session_value, csrf_value = self.sign_in(claims=admin_claims())

        missing_csrf_response, _, _ = self.run_with_fakes(
            http_event("POST", "/auth/admin/users/client-sub/approve", cookies=[f"__Host-zlp_session={session_value}"]),
            fake_dynamo=fake_dynamo,
        )
        self.assertEqual(missing_csrf_response["statusCode"], 403)

        self_response, _, _ = self.run_with_fakes(
            http_event(
                "POST",
                "/auth/admin/users/admin-sub/approve",
                headers={"x-zlp-csrf": csrf_value},
                cookies=[f"__Host-zlp_session={session_value}", f"zlp_csrf={csrf_value}"],
            ),
            fake_dynamo=fake_dynamo,
        )
        self.assertEqual(self_response["statusCode"], 400)
        self.assertEqual(body(self_response)["error"], "Users cannot approve themselves")

    def test_csrf_rejects_mismatched_cookie_header_and_invalid_hash(self):
        _, fake_dynamo, _, session_value, csrf_value = self.sign_in(claims=admin_claims())

        mismatch_response, _, _ = self.run_with_fakes(
            http_event(
                "POST",
                "/auth/admin/users/client-sub/approve",
                headers={"x-zlp-csrf": csrf_value},
                cookies=[f"__Host-zlp_session={session_value}", "zlp_csrf=other-csrf"],
            ),
            fake_dynamo=fake_dynamo,
        )
        self.assertEqual(mismatch_response["statusCode"], 403)

        invalid_hash_response, _, _ = self.run_with_fakes(
            http_event(
                "POST",
                "/auth/admin/users/client-sub/approve",
                headers={"x-zlp-csrf": "other-csrf"},
                cookies=[f"__Host-zlp_session={session_value}", "zlp_csrf=other-csrf"],
            ),
            fake_dynamo=fake_dynamo,
        )
        self.assertEqual(invalid_hash_response["statusCode"], 403)
        self.assertNotIn(csrf_value, json.dumps(body(invalid_hash_response)))
        self.assertNotIn(session_value, json.dumps(body(invalid_hash_response)))

    def test_error_responses_do_not_echo_sensitive_request_values(self):
        event = http_event("POST", "/auth/session/signin", {
            "domain": "zoositioweb.com.mx",
            "authProfileId": "missing-profile",
            "email": "client@example.test",
            "password": "DoNotEchoPass123!",
            "accessToken": "do-not-echo-access-token",
            "clientSecret": "do-not-echo-client-secret",
        })

        response, _, _ = self.run_with_fakes(event)
        response_json = json.dumps(response)

        self.assertNotEqual(response["statusCode"], 200)
        for forbidden in [
            "client@example.test",
            "DoNotEchoPass123!",
            "do-not-echo-access-token",
            "do-not-echo-client-secret",
        ]:
            self.assertNotIn(forbidden, response_json)

    def test_csrf_names_can_be_profile_configured(self):
        env = {
            "AUTH_ADMIN_CONFIG_JSON_BASE64": encoded_config(session={
                "csrfCookieName": "zoosite_csrf",
                "csrfHeaderName": "X-Zoosite-CSRF",
            })
        }
        response, fake_dynamo, _, session_value, csrf_value = self.sign_in(claims=admin_claims(), env=env)
        self.assertIn("zoosite_csrf=csrf-value", "\n".join(response.get("cookies") or []))
        tenant_key = "zoositioweb.com.mx#staff#test"
        fake_dynamo.users[(tenant_key, "USER#client-sub")] = {
            "tenantProfileKey": tenant_key,
            "subject": "client-sub",
            "username": "client@example.test",
            "email": "client@example.test",
            "roles": ["zoosite-client"],
            "approvalStatus": "pending",
            "enabled": True,
        }

        approved, _, _ = self.run_with_fakes(
            http_event(
                "POST",
                "/auth/admin/users/client-sub/approve",
                body={"groups": ["zoosite-client"]},
                headers={"X-Zoosite-CSRF": csrf_value},
                cookies=[f"__Host-zlp_session={session_value}", f"zoosite_csrf={csrf_value}"],
            ),
            fake_dynamo=fake_dynamo,
            env=env,
        )

        self.assertEqual(approved["statusCode"], 200)

    def test_approve_user_updates_status_groups_and_audit(self):
        admin_claims = {
            "sub": "admin-sub",
            "email": "admin@example.test",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            "aud": "public-client-id",
            "token_use": "id",
            "custom:tenant_id": "zoosite",
            "custom:zoolanding_env": "test",
            "cognito:groups": ["zoosite-admin"],
            "exp": 4102444800,
        }
        _, fake_dynamo, fake_cognito, session_value, csrf_value = self.sign_in(claims=admin_claims)
        tenant_key = "zoositioweb.com.mx#staff#test"
        fake_dynamo.users[(tenant_key, "USER#client-sub")] = {
            "tenantProfileKey": tenant_key,
            "subject": "client-sub",
            "username": "client@example.test",
            "email": "client@example.test",
            "roles": ["zoosite-client"],
            "approvalStatus": "pending",
            "enabled": True,
        }

        response, _, _ = self.run_with_fakes(
            http_event(
                "POST",
                "/auth/admin/users/client-sub/approve",
                body={"groups": ["zoosite-client", "zoosite-admin"]},
                headers={"x-zlp-csrf": csrf_value},
                cookies=[f"__Host-zlp_session={session_value}", f"zlp_csrf={csrf_value}"],
            ),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
        )

        self.assertEqual(response["statusCode"], 200)
        updated = body(response)["user"]
        self.assertEqual(updated["approvalStatus"], "approved")
        self.assertEqual(updated["roles"], ["zoosite-client", "zoosite-admin"])
        self.assertIn(("admin_add_user_to_group", {
            "UserPoolId": "us-east-1_pool",
            "Username": "client@example.test",
            "GroupName": "zoosite-admin",
        }), fake_cognito.calls)
        self.assertEqual(fake_dynamo.audit[-1]["eventType"], "user-approved")
        self.assertEqual(fake_dynamo.audit[-1]["actorSubject"], "admin-sub")

    def test_signin_rejects_environment_mismatch_claims(self):
        claims = {
            "sub": "client-sub",
            "email": "client@example.test",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            "aud": "public-client-id",
            "token_use": "id",
            "custom:tenant_id": "zoosite",
            "custom:zoolanding_env": "prod",
            "cognito:groups": ["zoosite-client"],
            "exp": 4102444800,
        }

        response, _, _ = self.run_with_fakes(http_event("POST", "/auth/session/signin", {
            "domain": "zoositioweb.com.mx",
            "authProfileId": "staff",
            "email": "client@example.test",
            "password": "ValidPass123!",
        }), claims=claims)

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(body(response)["error"], "Sign-in failed")

    def test_signin_rejects_non_id_token_claims(self):
        claims = {
            "sub": "client-sub",
            "email": "client@example.test",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            "aud": "public-client-id",
            "token_use": "access",
            "custom:tenant_id": "zoosite",
            "custom:zoolanding_env": "test",
            "cognito:groups": ["zoosite-client"],
            "exp": 4102444800,
        }

        response, _, _ = self.run_with_fakes(http_event("POST", "/auth/session/signin", {
            "domain": "zoositioweb.com.mx",
            "authProfileId": "staff",
            "email": "client@example.test",
            "password": "ValidPass123!",
        }), claims=claims)

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(body(response)["error"], "Sign-in failed")

    def test_group_updates_reject_non_manageable_groups(self):
        admin_claims = {
            "sub": "admin-sub",
            "email": "admin@example.test",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            "aud": "public-client-id",
            "token_use": "id",
            "custom:tenant_id": "zoosite",
            "custom:zoolanding_env": "test",
            "cognito:groups": ["zoosite-admin"],
            "exp": 4102444800,
        }
        _, fake_dynamo, _, session_value, csrf_value = self.sign_in(claims=admin_claims)
        tenant_key = "zoositioweb.com.mx#staff#test"
        fake_dynamo.users[(tenant_key, "USER#client-sub")] = {
            "tenantProfileKey": tenant_key,
            "subject": "client-sub",
            "username": "client@example.test",
            "email": "client@example.test",
            "roles": ["zoosite-client"],
            "approvalStatus": "pending",
            "enabled": True,
        }

        response, _, _ = self.run_with_fakes(
            http_event(
                "POST",
                "/auth/admin/users/client-sub/groups",
                body={"groups": ["zoosite-owner"]},
                headers={"x-zlp-csrf": csrf_value},
                cookies=[f"__Host-zlp_session={session_value}", f"zlp_csrf={csrf_value}"],
            ),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(body(response)["error"], "Requested groups are not manageable")

    def test_group_updates_use_cognito_groups_as_source_of_truth(self):
        admin_claims = {
            "sub": "admin-sub",
            "email": "admin@example.test",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            "aud": "public-client-id",
            "token_use": "id",
            "custom:tenant_id": "zoosite",
            "custom:zoolanding_env": "test",
            "cognito:groups": ["zoosite-admin"],
            "exp": 4102444800,
        }
        _, fake_dynamo, _, session_value, csrf_value = self.sign_in(claims=admin_claims)
        tenant_key = "zoositioweb.com.mx#staff#test"
        fake_dynamo.users[(tenant_key, "USER#client-sub")] = {
            "tenantProfileKey": tenant_key,
            "subject": "client-sub",
            "username": "client@example.test",
            "email": "client@example.test",
            "roles": ["zoosite-client"],
            "approvalStatus": "approved",
            "enabled": True,
        }
        fake_cognito = FakeCognito(groups_by_username={
            "client@example.test": ["zoosite-client", "zoosite-admin"],
        })

        response, _, _ = self.run_with_fakes(
            http_event(
                "POST",
                "/auth/admin/users/client-sub/groups",
                body={"groups": ["zoosite-client"]},
                headers={"x-zlp-csrf": csrf_value},
                cookies=[f"__Host-zlp_session={session_value}", f"zlp_csrf={csrf_value}"],
            ),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
        )

        self.assertEqual(response["statusCode"], 200)
        self.assertIn(("admin_list_groups_for_user", {
            "UserPoolId": "us-east-1_pool",
            "Username": "client@example.test",
        }), fake_cognito.calls)
        self.assertIn(("admin_remove_user_from_group", {
            "UserPoolId": "us-east-1_pool",
            "Username": "client@example.test",
            "GroupName": "zoosite-admin",
        }), fake_cognito.calls)

    def test_suspend_and_reactivate_user_write_audit(self):
        admin_claims = {
            "sub": "admin-sub",
            "email": "admin@example.test",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            "aud": "public-client-id",
            "token_use": "id",
            "custom:tenant_id": "zoosite",
            "custom:zoolanding_env": "test",
            "cognito:groups": ["zoosite-admin"],
            "exp": 4102444800,
        }
        _, fake_dynamo, fake_cognito, session_value, csrf_value = self.sign_in(claims=admin_claims)
        tenant_key = "zoositioweb.com.mx#staff#test"
        fake_dynamo.users[(tenant_key, "USER#client-sub")] = {
            "tenantProfileKey": tenant_key,
            "subject": "client-sub",
            "username": "client@example.test",
            "email": "client@example.test",
            "roles": ["zoosite-client"],
            "approvalStatus": "approved",
            "enabled": True,
        }
        cookies = [f"__Host-zlp_session={session_value}", f"zlp_csrf={csrf_value}"]
        headers = {"x-zlp-csrf": csrf_value}

        suspend_response, _, _ = self.run_with_fakes(
            http_event("POST", "/auth/admin/users/client-sub/suspend", headers=headers, cookies=cookies),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
        )
        reactivate_response, _, _ = self.run_with_fakes(
            http_event("POST", "/auth/admin/users/client-sub/reactivate", headers=headers, cookies=cookies),
            fake_dynamo=fake_dynamo,
            fake_cognito=fake_cognito,
        )

        self.assertEqual(suspend_response["statusCode"], 200)
        self.assertEqual(reactivate_response["statusCode"], 200)
        self.assertIn(("admin_disable_user", {
            "UserPoolId": "us-east-1_pool",
            "Username": "client@example.test",
        }), fake_cognito.calls)
        self.assertIn(("admin_enable_user", {
            "UserPoolId": "us-east-1_pool",
            "Username": "client@example.test",
        }), fake_cognito.calls)
        self.assertEqual([entry["eventType"] for entry in fake_dynamo.audit[-2:]], [
            "user-suspended",
            "user-reactivated",
        ])

    def test_logout_revokes_session_and_clears_cookies(self):
        _, fake_dynamo, _, session_value, csrf_value = self.sign_in()

        response, _, _ = self.run_with_fakes(
            http_event(
                "POST",
                "/auth/session/logout",
                headers={"x-zlp-csrf": csrf_value},
                cookies=[f"__Host-zlp_session={session_value}", f"zlp_csrf={csrf_value}"],
            ),
            fake_dynamo=fake_dynamo,
        )

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body(response)["status"], "signed-out")
        self.assertIn("Max-Age=0", "\n".join(response.get("cookies") or []))

    def test_template_grants_cognito_challenge_permissions_to_auth_admin_role(self):
        with open(os.path.join(os.path.dirname(__file__), os.pardir, "template.yaml"), encoding="utf-8") as template_file:
            template = template_file.read()

        for action in (
            "cognito-idp:AdminGetUser",
            "cognito-idp:AssociateSoftwareToken",
            "cognito-idp:RespondToAuthChallenge",
            "cognito-idp:SetUserMFAPreference",
            "cognito-idp:VerifySoftwareToken",
        ):
            self.assertIn(action, template)
        self.assertIn("Ref: CognitoUserPoolArns", template)
        self.assertIn("/auth/session/mfa/disable", template)


if __name__ == "__main__":
    unittest.main()
