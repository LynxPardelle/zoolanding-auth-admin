import json
import os
import sys
import types
import unittest
from unittest.mock import patch

import auth_admin_session_v2 as session_v2
from tests import test_auth_admin_session_v2 as flow_tests


ADMIN_HOST = "admin-test.thehairnarrative.com"
ADMIN_ORIGIN = f"https://{ADMIN_HOST}"


def event(method, path, body=None):
    return {
        "version": "2.0",
        "rawPath": path,
        "headers": {
            "host": ADMIN_HOST,
            "origin": ADMIN_ORIGIN,
            "x-forwarded-host": ADMIN_HOST,
            "x-zlp-viewer-ip": "203.0.113.50",
        },
        "requestContext": {
            "authorizer": {
                "lambda": {
                    "originVerified": True,
                    "viewerIp": "203.0.113.50",
                }
            },
            "http": {
                "method": method,
                "path": path,
                "sourceIp": "203.0.113.50",
            }
        },
        "body": json.dumps(body) if body is not None else None,
    }


class AuthAdminV2SecurityEdgeTests(unittest.TestCase):
    def setUp(self):
        # The new optional QA lookup must not mask the downstream failure under test.
        current_client = patch.object(session_v2, "_current_user_client", return_value=flow_tests.FakeV2Store())
        current_client.start()
        self.addCleanup(current_client.stop)

    @staticmethod
    def _seed_enrollment(store, *, raw_state="enrollment-state", raw_csrf="enrollment-csrf"):
        record = {
                "recordType": "authMfaEnrollmentV2",
                "stateIdHash": flow_tests.hash_text(raw_state),
                "csrfHash": flow_tests.hash_text(raw_csrf),
                "scope": dict(session_v2._SCOPE),
                "accountHash": flow_tests.hash_text("owner@example.test"),
                "username": "owner@example.test",
                "cognitoSession": "associated-session",
                "createdAt": flow_tests.NOW,
                "expiresAt": flow_tests.NOW + session_v2.STATE_SECONDS,
                "claimedAt": None,
                "consumedAt": None,
            }
        record["stateBindingHash"] = session_v2._ephemeral_state_binding_hash(record)
        store.put_ephemeral(record)

    def test_options_is_not_a_wildcard_route(self):
        with patch.object(
            session_v2, "_require_active_service_binding", return_value={}
        ):
            response = session_v2.lambda_handler(
                event("OPTIONS", "/auth-v2/not-in-the-manifest"), object()
            )

        self.assertEqual(response["statusCode"], 404)

    def test_password_only_provider_result_cannot_create_a_session(self):
        with self.assertRaises(session_v2.AuthV2Unavailable):
            session_v2._provider_result(
                {"AuthenticationResult": {"IdToken": "password-only-token"}},
                account_hash="a" * 64,
                fallback_username="owner@example.test",
                allow_session=False,
            )

        accepted = session_v2._provider_result(
            {"AuthenticationResult": {"IdToken": "mfa-token"}},
            account_hash="a" * 64,
            fallback_username="owner@example.test",
            allow_session=True,
        )
        self.assertEqual(accepted["kind"], "session")

    def test_new_password_required_fails_closed_on_unsatisfied_attributes(self):
        with self.assertRaises(session_v2.AuthV2Unavailable):
            session_v2._provider_result(
                {
                    "ChallengeName": "NEW_PASSWORD_REQUIRED",
                    "Session": "private-session",
                    "ChallengeParameters": {
                        "USERNAME": "owner@example.test",
                        "requiredAttributes": '["userAttributes.email"]',
                    },
                },
                account_hash="c" * 64,
                fallback_username="owner@example.test",
                allow_session=False,
            )

    def test_jwk_network_failure_is_unavailable_not_bad_credentials(self):
        class EndpointConnectionError(RuntimeError):
            pass

        class FakeJwkClient:
            def __init__(self, url):
                self.url = url

            def get_signing_key_from_jwt(self, token):
                raise EndpointConnectionError("private endpoint detail")

        fake_jwt = types.ModuleType("jwt")
        fake_jwt.PyJWKClient = FakeJwkClient
        fake_jwt.decode = lambda *args, **kwargs: {}
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
            with self.assertRaises(session_v2.AuthV2Unavailable):
                session_v2._verify_id_token("signed-id-token")

    def test_missing_cognito_configuration_fails_before_store_or_provider(self):
        clean_environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("THN_AUTH_V2_COGNITO_")
        }
        with (
            patch.dict(os.environ, clean_environment, clear=True),
            patch.object(
                session_v2, "_require_active_service_binding", return_value={}
            ),
            patch.object(
                session_v2,
                "_session_store",
                side_effect=AssertionError("store must not be touched"),
            ),
            patch.object(
                session_v2,
                "_cognito_client",
                side_effect=AssertionError("provider must not be touched"),
            ),
        ):
            response = session_v2.lambda_handler(
                event(
                    "POST",
                    "/auth-v2/session/signin",
                    {"email": "owner@example.test", "password": "ValidPass123!"},
                ),
                object(),
            )

        self.assertEqual(response["statusCode"], 503)
        self.assertEqual(json.loads(response["body"])["errorCode"], "auth_unavailable")

    def test_transient_provider_failure_releases_capacity_and_returns_503(self):
        class ProviderUnavailable(RuntimeError):
            response = {"Error": {"Code": "InternalErrorException"}}

        class Store:
            def __init__(self):
                self.released = []

            def reserve_failure_attempt(self, *args, **kwargs):
                return {
                    "mode": "reserved",
                    "failureKeys": ["account", "ip"],
                    "reservationId": "a" * 32,
                }

            def release_failure_attempt(self, reservation, *, now):
                self.released.append((reservation, now))

        class Cognito:
            def admin_initiate_auth(self, **kwargs):
                raise ProviderUnavailable("private provider detail")

        store = Store()
        with (
            patch.object(
                session_v2, "_require_active_service_binding", return_value={}
            ),
            patch.object(
                session_v2,
                "_cognito_configuration",
                return_value=("us-east-1", "us-east-1_THNTEST", "thnv2client"),
            ),
            patch.object(session_v2, "_session_store", return_value=store),
            patch.object(session_v2, "_cognito_client", return_value=Cognito()),
            patch.object(session_v2, "_now_epoch", return_value=1_800_000_000),
        ):
            response = session_v2.lambda_handler(
                event(
                    "POST",
                    "/auth-v2/session/signin",
                    {"email": "owner@example.test", "password": "ValidPass123!"},
                ),
                object(),
            )

        self.assertEqual(response["statusCode"], 503)
        self.assertEqual(json.loads(response["body"])["errorCode"], "auth_unavailable")
        self.assertEqual(len(store.released), 1)

    def test_current_user_read_failure_is_not_reported_as_bad_credentials(self):
        with (
            patch.object(
                session_v2,
                "_verify_id_token",
                return_value={"sub": "owner-123", "token_use": "id"},
            ),
            patch.object(
                session_v2,
                "_state_for_subject",
                side_effect=session_v2.CurrentUserStateUnavailable(
                    "private storage detail"
                ),
            ),
        ):
            with self.assertRaises(session_v2.AuthV2Unavailable):
                session_v2._new_session_response(
                    {"IdToken": "signed-token"}, account_hash="b" * 64
                )

    def test_ephemeral_storage_failure_is_reported_as_unavailable(self):
        class Store:
            def put_ephemeral(self, item):
                raise RuntimeError("private storage failure")

        with (
            patch.object(session_v2, "_session_store", return_value=Store()),
            patch.object(session_v2, "_random_urlsafe", side_effect=("state", "csrf")),
            patch.object(session_v2, "_now_epoch", return_value=1_800_000_000),
        ):
            with self.assertRaises(session_v2.AuthV2Unavailable):
                session_v2._new_challenge_response(
                    {
                        "accountHash": "d" * 64,
                        "username": "owner@example.test",
                        "challengeName": "SOFTWARE_TOKEN_MFA",
                        "cognitoSession": "private-session",
                    }
                )

    def test_mfa_setup_can_rotate_to_the_followup_software_token_challenge(self):
        store = flow_tests.FakeV2Store()
        self._seed_enrollment(store)
        cognito = flow_tests.FakeCognito(
            verify_response={"Status": "SUCCESS", "Session": "verified-session"},
            challenge_response={
                "ChallengeName": "SOFTWARE_TOKEN_MFA",
                "Session": "followup-mfa-session",
                "ChallengeParameters": {"USERNAME": "owner@example.test"},
            },
        )
        tokens = iter(("followup-challenge", "followup-csrf"))
        with (
            patch.object(
                session_v2, "_require_active_service_binding", return_value={}
            ),
            patch.object(
                session_v2,
                "_cognito_configuration",
                return_value=("us-east-1", "us-east-1_THNTEST", "thnv2client"),
            ),
            patch.object(session_v2, "_session_store", return_value=store),
            patch.object(session_v2, "_current_user_client", return_value=store),
            patch.object(session_v2, "_cognito_client", return_value=cognito),
            patch.object(session_v2, "_now_epoch", return_value=flow_tests.NOW),
            patch.object(
                session_v2, "_random_urlsafe", side_effect=lambda *_: next(tokens)
            ),
        ):
            response = session_v2.lambda_handler(
                flow_tests.v2_event(
                    "POST",
                    "/auth-v2/session/mfa/verify",
                    {"code": "123456"},
                    cookies=[
                        f"{flow_tests.ENROLLMENT_COOKIE}=enrollment-state",
                        f"{flow_tests.ENROLLMENT_CSRF_COOKIE}=enrollment-csrf",
                    ],
                    headers={"x-zlp-csrf": "enrollment-csrf"},
                ),
                object(),
            )

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(json.loads(response["body"])["challengeName"], "SOFTWARE_TOKEN_MFA")
        followup = store.ephemeral[flow_tests.hash_text("followup-challenge")]
        self.assertEqual(followup["cognitoSession"], "followup-mfa-session")
        self.assertEqual(store.sessions, {})
        cookies = response.get("cookies") or []
        self.assertTrue(
            any(
                cookie.startswith(f"{flow_tests.ENROLLMENT_COOKIE}=")
                and "Max-Age=0" in cookie
                for cookie in cookies
            )
        )

    def test_mfa_setup_requires_the_rotated_verify_session(self):
        store = flow_tests.FakeV2Store()
        self._seed_enrollment(store)
        cognito = flow_tests.FakeCognito(
            verify_response={"Status": "SUCCESS"},
            challenge_response={
                "AuthenticationResult": {"IdToken": "must-not-be-used"}
            },
        )
        with (
            patch.object(
                session_v2, "_require_active_service_binding", return_value={}
            ),
            patch.object(
                session_v2,
                "_cognito_configuration",
                return_value=("us-east-1", "us-east-1_THNTEST", "thnv2client"),
            ),
            patch.object(session_v2, "_session_store", return_value=store),
            patch.object(session_v2, "_cognito_client", return_value=cognito),
            patch.object(session_v2, "_now_epoch", return_value=flow_tests.NOW),
        ):
            response = session_v2.lambda_handler(
                flow_tests.v2_event(
                    "POST",
                    "/auth-v2/session/mfa/verify",
                    {"code": "123456"},
                    cookies=[
                        f"{flow_tests.ENROLLMENT_COOKIE}=enrollment-state",
                        f"{flow_tests.ENROLLMENT_CSRF_COOKIE}=enrollment-csrf",
                    ],
                    headers={"x-zlp-csrf": "enrollment-csrf"},
                ),
                object(),
            )

        self.assertEqual(response["statusCode"], 503)
        self.assertEqual(store.sessions, {})
        self.assertEqual(
            [name for name, _ in cognito.calls].count("admin_respond_to_auth_challenge"),
            0,
        )


if __name__ == "__main__":
    unittest.main()
