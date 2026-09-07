import copy
import json
import sys
import types
import unittest
from unittest.mock import patch

import auth_admin_session_v2 as session_v2
from tests import test_auth_admin_session_v2 as flow_tests


NOW = 1_800_000_000


class ReservingFlowStore(flow_tests.FakeV2Store):
    def __init__(self):
        super().__init__()
        self.released_reservations = []

    def reserve_failure_attempt(
        self,
        operation,
        account_hash,
        ip_hash,
        *,
        now,
        window_seconds,
        account_limit,
        ip_limit,
    ):
        self.calls.append(
            (
                "reserve_failure_attempt",
                operation,
                account_hash,
                ip_hash,
                now,
                window_seconds,
                account_limit,
                ip_limit,
            )
        )
        return {
            "mode": "reserved",
            "failureKeys": ["account", "ip"],
            "reservationId": "a" * 32,
        }

    def release_failure_attempt(self, reservation, *, now):
        self.released_reservations.append((copy.deepcopy(reservation), now))


class SuccessfulCognito:
    def __init__(self, response):
        self.response = copy.deepcopy(response)

    def admin_initiate_auth(self, **kwargs):
        return copy.deepcopy(self.response)


class FailingLowLevelDynamo:
    class NonConditionalDynamoFailure(RuntimeError):
        response = {"Error": {"Code": "InternalServerError"}}

    @classmethod
    def _fail(cls, **kwargs):
        raise cls.NonConditionalDynamoFailure("private low-level DynamoDB detail")

    put_item = _fail
    get_item = _fail
    update_item = _fail
    transact_write_items = _fail


class AuthAdminV2ReviewFindingTests(unittest.TestCase):
    def _run_signin(self, provider_response):
        store = ReservingFlowStore()
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
            patch.object(
                session_v2,
                "_cognito_client",
                return_value=SuccessfulCognito(provider_response),
            ),
            patch.object(session_v2, "_now_epoch", return_value=NOW),
        ):
            response = session_v2.lambda_handler(
                flow_tests.signin_event(), object()
            )
        return response, store

    def test_real_pyjwk_connection_error_is_503_and_releases_throttle_capacity(self):
        class PyJWKClientConnectionError(RuntimeError):
            """Exact PyJWT runtime exception identity used by the offline unit test."""

        PyJWKClientConnectionError.__module__ = "jwt.exceptions"

        class FailingJwkClient:
            def __init__(self, url):
                self.url = url

            def get_signing_key_from_jwt(self, token):
                raise PyJWKClientConnectionError("private JWK transport detail")

        fake_jwt = types.ModuleType("jwt")
        fake_jwt.PyJWKClient = FailingJwkClient
        fake_jwt.decode = lambda *args, **kwargs: {}
        fake_jwt_exceptions = types.ModuleType("jwt.exceptions")
        fake_jwt_exceptions.PyJWKClientConnectionError = PyJWKClientConnectionError

        raw_state = "challenge-token"
        raw_csrf = "challenge-csrf"
        store = ReservingFlowStore()
        challenge = {
                "recordType": "authChallengeV2",
                "stateIdHash": flow_tests.hash_text(raw_state),
                "csrfHash": flow_tests.hash_text(raw_csrf),
                "scope": copy.deepcopy(session_v2._SCOPE),
                "accountHash": flow_tests.hash_text("owner@example.test"),
                "username": "owner@example.test",
                "challengeName": "SOFTWARE_TOKEN_MFA",
                "cognitoSession": "private-cognito-session",
                "createdAt": NOW,
                "expiresAt": NOW + session_v2.STATE_SECONDS,
                "claimedAt": None,
                "consumedAt": None,
            }
        challenge["stateBindingHash"] = session_v2._ephemeral_state_binding_hash(
            challenge
        )
        store.put_ephemeral(challenge)
        cognito = flow_tests.FakeCognito(
            challenge_response={
                "AuthenticationResult": {"IdToken": "signed-id-token"}
            }
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
            patch.object(session_v2, "_now_epoch", return_value=NOW),
            patch.dict(
                sys.modules,
                {"jwt": fake_jwt, "jwt.exceptions": fake_jwt_exceptions},
            ),
        ):
            response = session_v2.lambda_handler(
                flow_tests.v2_event(
                    "POST",
                    "/auth-v2/session/challenge/respond",
                    {"code": "123456"},
                    cookies=[
                        f"{flow_tests.CHALLENGE_COOKIE}={raw_state}",
                        f"{flow_tests.CHALLENGE_CSRF_COOKIE}={raw_csrf}",
                    ],
                    headers={"x-zlp-csrf": raw_csrf},
                ),
                object(),
            )

        self.assertEqual(response["statusCode"], 503)
        self.assertEqual(json.loads(response["body"])["errorCode"], "auth_unavailable")
        self.assertEqual(len(store.released_reservations), 1)

    def test_successful_but_impossible_cognito_shapes_are_503_and_release_capacity(self):
        impossible_shapes = (
            {},
            {"ResponseMetadata": {"HTTPStatusCode": 200}},
            {
                "ChallengeName": "SOFTWARE_TOKEN_MFA",
                "ChallengeParameters": {"USERNAME": "owner@example.test"},
            },
            {
                "ChallengeName": "SOFTWARE_TOKEN_MFA",
                "Session": "private-cognito-session",
                "ChallengeParameters": {"USERNAME": "owner@example.test"},
                "AuthenticationResult": {"IdToken": "mutually-exclusive-result"},
            },
        )

        for provider_response in impossible_shapes:
            with self.subTest(provider_response=provider_response):
                response, store = self._run_signin(provider_response)
                self.assertEqual(response["statusCode"], 503)
                self.assertEqual(
                    json.loads(response["body"])["errorCode"], "auth_unavailable"
                )
                self.assertEqual(len(store.released_reservations), 1)

    def test_nonconditional_dynamodb_failures_map_to_auth_unavailable(self):
        operations = (
            (
                "put_session",
                lambda store: store.put_session({"sessionIdHash": "session-hash"}),
            ),
            (
                "get_session",
                lambda store: store.get_session(
                    "session-hash", consistent_read=True
                ),
            ),
            (
                "touch_session",
                lambda store: store.touch_session(
                    "session-hash",
                    now=NOW,
                    idle_expires_at=NOW + session_v2.SESSION_IDLE_SECONDS,
                    absolute_expires_at=NOW + session_v2.SESSION_ABSOLUTE_SECONDS,
                    subject="owner-123",
                    account_purpose="client-owner",
                    session_version=1,
                ),
            ),
            (
                "rotate_session",
                lambda store: store.rotate_session(
                    "old-session-hash",
                    {
                        "recordType": "authSessionV2",
                        "scope": copy.deepcopy(session_v2._SCOPE),
                        "sessionIdHash": "new-session-hash",
                        "sessionVersion": 1,
                    },
                    now=NOW,
                ),
            ),
            (
                "revoke_session",
                lambda store: store.revoke_session("session-hash", now=NOW),
            ),
            (
                "put_ephemeral",
                lambda store: store.put_ephemeral({"stateIdHash": "state-hash"}),
            ),
            (
                "get_ephemeral",
                lambda store: store.get_ephemeral(
                    "state-hash", consistent_read=True
                ),
            ),
            (
                "claim_ephemeral",
                lambda store: store.claim_ephemeral(
                    "d" * 64,
                    expected_type="authChallengeV2",
                    expected_binding_hash="e" * 64,
                    now=NOW,
                ),
            ),
            (
                "release_ephemeral_claim",
                lambda store: store.release_ephemeral_claim(
                    "d" * 64,
                    now=NOW,
                    claim_token="claim-token",
                    expected_binding_hash="e" * 64,
                ),
            ),
            (
                "consume_ephemeral_claim",
                lambda store: store.consume_ephemeral_claim(
                    "d" * 64,
                    now=NOW,
                    claim_token="claim-token",
                    expected_binding_hash="e" * 64,
                ),
            ),
        )

        for name, operation in operations:
            with self.subTest(operation=name):
                store = session_v2.DynamoAuthV2Store(FailingLowLevelDynamo())
                with self.assertRaises(session_v2.AuthV2Unavailable):
                    operation(store)

    def test_success_response_survives_post_commit_throttle_cleanup_outage(self):
        class CleanupFailureStore(ReservingFlowStore):
            def release_failure_attempt(self, reservation, *, now):
                raise session_v2.AuthV2Unavailable()

        store = CleanupFailureStore()
        cognito = flow_tests.FakeCognito(
            auth_response={
                "ChallengeName": "SOFTWARE_TOKEN_MFA",
                "Session": "private-session",
                "ChallengeParameters": {"USERNAME": "owner@example.test"},
            }
        )
        with (
            patch.object(session_v2, "_require_active_service_binding", return_value={}),
            patch.object(
                session_v2,
                "_cognito_configuration",
                return_value=("us-east-1", "us-east-1_THNTEST", "thnv2client"),
            ),
            patch.object(session_v2, "_session_store", return_value=store),
            patch.object(session_v2, "_cognito_client", return_value=cognito),
            patch.object(session_v2, "_now_epoch", return_value=NOW),
            patch.object(
                session_v2,
                "_random_urlsafe",
                side_effect=("challenge-state", "challenge-csrf"),
            ),
        ):
            response = session_v2.lambda_handler(flow_tests.signin_event(), object())

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(
            json.loads(response["body"])["status"], "challenge-required"
        )

    def test_throttle_reserve_and_release_reads_map_outages_to_unavailable(self):
        reserve_store = session_v2.DynamoAuthV2Store(FailingLowLevelDynamo())
        with self.assertRaises(session_v2.AuthV2Unavailable):
            reserve_store.reserve_failure_attempt(
                "signin",
                "a" * 64,
                "b" * 64,
                now=NOW,
                window_seconds=900,
                account_limit=5,
                ip_limit=10,
            )

        release_store = session_v2.DynamoAuthV2Store(FailingLowLevelDynamo())
        with self.assertRaises(session_v2.AuthV2Unavailable):
            release_store.release_failure_attempt(
                {
                    "mode": "reserved",
                    "failureKeys": ["signin#account#a", "signin#ip#b"],
                    "reservationId": "c" * 32,
                    "windowSeconds": 900,
                },
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
