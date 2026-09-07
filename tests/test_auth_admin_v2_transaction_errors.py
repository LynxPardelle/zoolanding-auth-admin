import copy
import unittest
from unittest.mock import patch

import auth_admin_session_v2 as session_v2
from tests import test_auth_admin_session_v2 as flow_tests
from tests.test_auth_admin_session_v2_store import (
    FakeLowLevelDynamo,
    InspectableDynamoAuthV2Store,
    NOW,
)
from tests.test_auth_admin_v2_atomic_store_contract import session_record


class TransactionCanceledException(RuntimeError):
    def __init__(self, cancellation_codes):
        super().__init__("private DynamoDB transaction detail")
        self.response = {
            "Error": {"Code": "TransactionCanceledException"},
            "CancellationReasons": [
                {"Code": code} for code in cancellation_codes
            ],
        }


class CorruptClaimStore:
    def __init__(self, record, *, return_none=False):
        self.record = copy.deepcopy(record)
        self.return_none = return_none
        self.release_calls = []

    def get_ephemeral(self, state_id_hash, *, consistent_read):
        self.last_get = (state_id_hash, consistent_read)
        return copy.deepcopy(self.record)

    def claim_ephemeral(
        self,
        state_id_hash,
        *,
        expected_type,
        expected_binding_hash,
        now,
    ):
        self.last_claim = (
            state_id_hash,
            expected_type,
            expected_binding_hash,
            now,
        )
        if self.return_none:
            return None
        claimed = copy.deepcopy(self.record)
        claimed["claimedAt"] = now
        claimed["claimToken"] = "raw-server-side-claim-token"
        # Simulate a non-null ALL_NEW response whose immutable state no longer
        # matches the binding validated by the preceding consistent read.
        claimed["username"] = "corrupt-returned-username"
        return claimed

    def release_ephemeral_claim(
        self,
        state_id_hash,
        *,
        now,
        claim_token,
        expected_binding_hash,
    ):
        self.release_calls.append(
            {
                "stateIdHash": state_id_hash,
                "now": now,
                "claimToken": claim_token,
                "expectedBindingHash": expected_binding_hash,
            }
        )
        return True


def challenge_fixture():
    raw_state = "challenge-state"
    raw_csrf = "challenge-csrf"
    record = {
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
    record["stateBindingHash"] = session_v2._ephemeral_state_binding_hash(record)
    event = flow_tests.v2_event(
        "POST",
        "/auth-v2/session/challenge/respond",
        {"code": "123456"},
        cookies=[
            f"{flow_tests.CHALLENGE_COOKIE}={raw_state}",
            f"{flow_tests.CHALLENGE_CSRF_COOKIE}={raw_csrf}",
        ],
        headers={"x-zlp-csrf": raw_csrf},
    )
    return event, record


class AuthAdminV2TransactionErrorContractTests(unittest.TestCase):
    def _transition_with_cancellation(self, cancellation_codes):
        client = FakeLowLevelDynamo(
            transact_responses=[TransactionCanceledException(cancellation_codes)]
        )
        store = InspectableDynamoAuthV2Store(client)
        return store.transition_ephemeral_claim(
            "d" * 64,
            expected_type="authChallengeV2",
            expected_binding_hash="f" * 64,
            expected_account_hash="a" * 64,
            claim_token="raw-server-side-claim-token",
            now=NOW + 1,
            next_item=session_record(),
        )

    def _invoke_corrupt_claim(self, store):
        event, record = challenge_fixture()
        with patch.object(session_v2, "_now_epoch", return_value=NOW + 1):
            return session_v2._claim_ephemeral(
                event,
                store,
                cookie_name=flow_tests.CHALLENGE_COOKIE,
                csrf_cookie_name=flow_tests.CHALLENGE_CSRF_COOKIE,
                expected_type="authChallengeV2",
            ), record

    def test_transient_transaction_cancellation_is_unavailable(self):
        transient_cancellations = (
            ("None", "ThrottlingError", "None"),
            ("TransactionConflict", "None", "None"),
            ("None", "InternalServerError", "None"),
            ("ConditionalCheckFailed", "ThrottlingError", "None"),
        )

        for cancellation_codes in transient_cancellations:
            with self.subTest(cancellation_codes=cancellation_codes):
                with self.assertRaises(session_v2.AuthV2Unavailable):
                    self._transition_with_cancellation(cancellation_codes)

    def test_condition_only_transaction_cancellation_remains_auth_conflict(self):
        committed = self._transition_with_cancellation(
            ("None", "ConditionalCheckFailed", "None")
        )

        self.assertFalse(committed)

    def test_condition_only_cancellation_requires_one_reason_per_transaction_item(self):
        malformed_reason_counts = (
            ("ConditionalCheckFailed",),
            ("None", "ConditionalCheckFailed"),
            ("None", "ConditionalCheckFailed", "None", "None"),
        )

        for cancellation_codes in malformed_reason_counts:
            with self.subTest(cancellation_codes=cancellation_codes):
                with self.assertRaises(session_v2.AuthV2Unavailable):
                    self._transition_with_cancellation(cancellation_codes)

    def test_non_string_cancellation_reason_code_is_unavailable(self):
        malformed_codes = ([], {})

        for malformed_code in malformed_codes:
            with self.subTest(malformed_code=malformed_code):
                with self.assertRaises(session_v2.AuthV2Unavailable):
                    self._transition_with_cancellation(
                        (malformed_code, "None", "None")
                    )

    def test_non_null_corrupt_claim_response_is_unavailable(self):
        _, record = challenge_fixture()
        store = CorruptClaimStore(record)

        try:
            self._invoke_corrupt_claim(store)
        except session_v2.AuthV2Error as exc:
            raised = exc
        else:
            self.fail("corrupt ALL_NEW response was accepted")

        self.assertIsInstance(raised, session_v2.AuthV2Unavailable)

    def test_non_null_corrupt_claim_is_released_best_effort(self):
        _, record = challenge_fixture()
        store = CorruptClaimStore(record)

        try:
            self._invoke_corrupt_claim(store)
        except session_v2.AuthV2Error:
            pass

        self.assertEqual(len(store.release_calls), 1)
        self.assertEqual(
            store.release_calls[0]["claimToken"], "raw-server-side-claim-token"
        )
        self.assertEqual(
            store.release_calls[0]["expectedBindingHash"],
            record["stateBindingHash"],
        )

    def test_conditional_claim_conflict_remains_auth_failure(self):
        _, record = challenge_fixture()
        store = CorruptClaimStore(record, return_none=True)

        with self.assertRaises(session_v2.AuthV2AuthFailed):
            self._invoke_corrupt_claim(store)

        self.assertEqual(store.release_calls, [])

    def _assert_corrupt_low_level_claim_is_released(self, update_response):
        raw_claim_token = "local-only-claim-token"
        client = FakeLowLevelDynamo(update_responses=[update_response, {}])
        store = session_v2.DynamoAuthV2Store(client)

        with patch.object(
            session_v2.secrets,
            "token_urlsafe",
            return_value=raw_claim_token,
        ):
            with self.assertRaises(session_v2.AuthV2Unavailable):
                store.claim_ephemeral(
                    "d" * 64,
                    expected_type="authChallengeV2",
                    expected_binding_hash="f" * 64,
                    now=NOW + 1,
                )

        update_calls = [call for call in client.calls if call[0] == "update_item"]
        self.assertEqual(len(update_calls), 2)
        release_request = update_calls[1][1]
        self.assertEqual(
            release_request["ExpressionAttributeValues"][":claimTokenHash"],
            {"S": session_v2._sha256(raw_claim_token)},
        )
        self.assertEqual(
            release_request["ExpressionAttributeValues"][":stateBindingHash"],
            {"S": "f" * 64},
        )
        self.assertNotIn(raw_claim_token, repr(client.calls))

    def test_missing_all_new_attributes_is_released_and_unavailable(self):
        self._assert_corrupt_low_level_claim_is_released({})

    def test_malformed_all_new_attributes_is_released_and_unavailable(self):
        self._assert_corrupt_low_level_claim_is_released(
            {"Attributes": {"stateIdHash": {"NULL": True}}}
        )


if __name__ == "__main__":
    unittest.main()
