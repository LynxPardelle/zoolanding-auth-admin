import copy
import unittest
from unittest.mock import patch

import auth_admin_session_v2 as session_v2
from tests.test_auth_admin_session_v2_store import (
    FakeLowLevelDynamo,
    InspectableDynamoAuthV2Store,
    NOW,
    decoded_item,
    encoded_item,
    sha256,
)


class ConditionalCheckFailedException(RuntimeError):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class ProvisionedThroughputExceededException(RuntimeError):
    response = {"Error": {"Code": "ProvisionedThroughputExceededException"}}


def session_record(*, session_id_hash="b" * 64):
    absolute = NOW + session_v2.SESSION_ABSOLUTE_SECONDS
    return {
        "recordType": "authSessionV2",
        "sessionIdHash": session_id_hash,
        "csrfHash": "c" * 64,
        "scope": copy.deepcopy(session_v2._SCOPE),
        "subject": "owner-123",
        "accountHash": "a" * 64,
        "accountPurpose": "client-owner",
        "cognitoUsername": "owner@example.test",
        "sessionVersion": 7,
        "roles": ["journal-owner"],
        "createdAt": NOW,
        "lastSeenAt": NOW,
        "idleExpiresAt": NOW + session_v2.SESSION_IDLE_SECONDS,
        "absoluteExpiresAt": absolute,
        "expiresAt": absolute,
        "revokedAt": None,
    }


def challenge_record(*, state_id_hash="d" * 64):
    value = {
        "recordType": "authChallengeV2",
        "stateIdHash": state_id_hash,
        "csrfHash": "e" * 64,
        "scope": copy.deepcopy(session_v2._SCOPE),
        "accountHash": "a" * 64,
        "username": "owner@example.test",
        "challengeName": "SOFTWARE_TOKEN_MFA",
        "cognitoSession": "private-session",
        "createdAt": NOW,
        "expiresAt": NOW + session_v2.STATE_SECONDS,
        "claimedAt": None,
        "consumedAt": None,
    }
    value["stateBindingHash"] = session_v2._ephemeral_state_binding_hash(value)
    return value


class AuthAdminV2AtomicStoreContractTests(unittest.TestCase):
    def setUp(self):
        table_patch = patch.multiple(
            session_v2,
            SESSION_TABLE_NAME="thn-v2-session-test",
            CHALLENGE_TABLE_NAME="thn-v2-challenge-test",
            THROTTLE_TABLE_NAME="thn-v2-throttle-test",
        )
        table_patch.start()
        self.addCleanup(table_patch.stop)

    def test_transition_consumes_claim_and_persists_session_in_one_transaction(self):
        client = FakeLowLevelDynamo()
        store = InspectableDynamoAuthV2Store(client)
        next_session = session_record()

        committed = store.transition_ephemeral_claim(
            "d" * 64,
            expected_type="authChallengeV2",
            expected_binding_hash="f" * 64,
            expected_account_hash="a" * 64,
            claim_token="raw-claim-token",
            now=NOW + 1,
            next_item=next_session,
        )

        self.assertTrue(committed)
        calls = [kwargs for name, kwargs in client.calls if name == "transact_write_items"]
        self.assertEqual(len(calls), 1)
        writes = calls[0]["TransactItems"]
        self.assertEqual(len(writes), 3)
        consume = writes[0]["Update"]
        target = writes[1]["Put"]
        self.assertEqual(consume["TableName"], "thn-v2-challenge-test")
        for guard in (
            "#recordType = :recordType",
            "#scope = :scope",
            "#stateBindingHash = :stateBindingHash",
            "#claimTokenHash = :claimTokenHash",
            "#expiresAt > :now",
            "attribute_not_exists(#consumedAt)",
        ):
            self.assertIn(guard, consume["ConditionExpression"])
        self.assertEqual(target["TableName"], "thn-v2-session-test")
        self.assertEqual(
            decoded_item(target["Item"]),
            {key: value for key, value in next_session.items() if value is not None},
        )
        self.assertNotIn("raw-claim-token", repr(writes))

    def test_transition_conditional_conflict_is_auth_failure_but_outage_is_unavailable(self):
        next_session = session_record()
        conditional = InspectableDynamoAuthV2Store(
            FakeLowLevelDynamo(transact_responses=[ConditionalCheckFailedException()])
        )
        outage = InspectableDynamoAuthV2Store(
            FakeLowLevelDynamo(
                transact_responses=[ProvisionedThroughputExceededException()]
            )
        )

        self.assertFalse(
            conditional.transition_ephemeral_claim(
                "d" * 64,
                expected_type="authChallengeV2",
                expected_binding_hash="f" * 64,
                expected_account_hash="a" * 64,
                claim_token="raw-claim-token",
                now=NOW + 1,
                next_item=next_session,
            )
        )
        with self.assertRaises(session_v2.AuthV2Unavailable):
            outage.transition_ephemeral_claim(
                "d" * 64,
                expected_type="authChallengeV2",
                expected_binding_hash="f" * 64,
                expected_account_hash="a" * 64,
                claim_token="raw-claim-token",
                now=NOW + 1,
                next_item=next_session,
            )

    def test_claim_errors_distinguish_conditional_conflict_from_storage_outage(self):
        conditional = InspectableDynamoAuthV2Store(
            FakeLowLevelDynamo(update_responses=[ConditionalCheckFailedException()])
        )
        outage = InspectableDynamoAuthV2Store(
            FakeLowLevelDynamo(
                update_responses=[ProvisionedThroughputExceededException()]
            )
        )

        self.assertIsNone(
            conditional.claim_ephemeral(
                "d" * 64,
                expected_type="authChallengeV2",
                expected_binding_hash="f" * 64,
                now=NOW,
            )
        )
        with self.assertRaises(session_v2.AuthV2Unavailable):
            outage.claim_ephemeral(
                "d" * 64,
                expected_type="authChallengeV2",
                expected_binding_hash="f" * 64,
                now=NOW,
            )

    def test_touch_is_monotonic_scoped_and_returns_a_valid_session(self):
        touched = session_record()
        touched["lastSeenAt"] = NOW + 1
        touched["idleExpiresAt"] = NOW + session_v2.SESSION_IDLE_SECONDS + 1
        client = FakeLowLevelDynamo(
            transact_responses=[{}],
            get_responses=[{"Item": encoded_item(**touched)}],
        )
        store = InspectableDynamoAuthV2Store(client)

        result = store.touch_session(
            touched["sessionIdHash"],
            now=NOW + 1,
            idle_expires_at=touched["idleExpiresAt"],
            absolute_expires_at=touched["absoluteExpiresAt"],
            subject=touched["subject"],
            account_purpose=touched["accountPurpose"],
            session_version=7,
        )

        self.assertEqual(result, touched)
        request = next(
            kwargs for name, kwargs in client.calls if name == "transact_write_items"
        )["TransactItems"][0]["Update"]
        for guard in (
            "attribute_exists(#sessionIdHash)",
            "#recordType = :recordType",
            "#scope = :scope",
            "#lastSeenAt <= :now",
        ):
            self.assertIn(guard, request["ConditionExpression"])

    def test_touch_atomically_fences_the_authoritative_current_user_state(self):
        touched = session_record()
        touched["lastSeenAt"] = NOW + 1
        touched["idleExpiresAt"] = NOW + session_v2.SESSION_IDLE_SECONDS + 1
        client = FakeLowLevelDynamo(
            transact_responses=[{}],
            get_responses=[{"Item": encoded_item(**touched)}],
        )
        store = InspectableDynamoAuthV2Store(client)

        result = store.touch_session(
            touched["sessionIdHash"],
            now=NOW + 1,
            idle_expires_at=touched["idleExpiresAt"],
            absolute_expires_at=touched["absoluteExpiresAt"],
            subject=touched["subject"],
            account_purpose=touched["accountPurpose"],
            session_version=touched["sessionVersion"],
        )

        self.assertEqual(result, touched)
        transaction = next(
            kwargs
            for name, kwargs in client.calls
            if name == "transact_write_items"
        )["TransactItems"]
        self.assertEqual(len(transaction), 2)
        session_update = transaction[0]["Update"]
        current_user_check = transaction[1]["ConditionCheck"]
        self.assertEqual(session_update["TableName"], "thn-v2-session-test")
        self.assertEqual(current_user_check["TableName"], session_v2.APPROVED_TABLE_NAME)
        self.assertEqual(
            decoded_item(current_user_check["Key"]),
            {
                "pk": session_v2.APPROVED_PARTITION_KEY,
                "sk": "SUBJECT#owner-123",
            },
        )
        for guard in (
            "#contractVersion = :contractVersion",
            "#scope = :scope",
            "#subject = :subject",
            "#accountPurpose = :accountPurpose",
            "#sessionVersion = :sessionVersion",
            "#enabled = :enabled",
        ):
            self.assertIn(guard, current_user_check["ConditionExpression"])
        self.assertIs(
            next(kwargs for name, kwargs in client.calls if name == "get_item")[
                "ConsistentRead"
            ],
            True,
        )

    def test_persisted_state_cannot_exceed_the_contract_ttl_by_one_second(self):
        idle_too_long = session_record()
        idle_too_long["idleExpiresAt"] = (
            idle_too_long["lastSeenAt"] + session_v2.SESSION_IDLE_SECONDS + 1
        )
        absolute_too_long = session_record()
        absolute_too_long["absoluteExpiresAt"] = (
            absolute_too_long["createdAt"] + session_v2.SESSION_ABSOLUTE_SECONDS + 1
        )
        absolute_too_long["expiresAt"] = absolute_too_long["absoluteExpiresAt"]

        self.assertFalse(session_v2._valid_session_record(idle_too_long, now=NOW))
        self.assertFalse(session_v2._valid_session_record(absolute_too_long, now=NOW))

        for record_type in ("authChallengeV2", "authMfaEnrollmentV2"):
            with self.subTest(record_type=record_type):
                ephemeral = challenge_record()
                ephemeral["recordType"] = record_type
                ephemeral["expiresAt"] = (
                    ephemeral["createdAt"] + session_v2.STATE_SECONDS + 1
                )
                if record_type == "authMfaEnrollmentV2":
                    ephemeral.pop("challengeName")
                ephemeral["stateBindingHash"] = (
                    session_v2._ephemeral_state_binding_hash(ephemeral)
                )
                self.assertFalse(
                    session_v2._valid_ephemeral_record(
                        ephemeral,
                        expected_type=record_type,
                        now=NOW,
                    )
                )

    def test_rotation_preserves_identity_purpose_and_same_session_version(self):
        client = FakeLowLevelDynamo()
        store = InspectableDynamoAuthV2Store(client)
        new_session = session_record()

        store.rotate_session("a" * 64, new_session, now=NOW + 1)

        transaction = client.calls[0][1]["TransactItems"]
        self.assertEqual(len(transaction), 3)
        update = transaction[0]["Update"]
        condition = update["ConditionExpression"]
        values = decoded_item(update["ExpressionAttributeValues"])
        for guard in (
            "#subject = :subject",
            "#accountHash = :accountHash",
            "#accountPurpose = :accountPurpose",
            "#cognitoUsername = :cognitoUsername",
            "#sessionVersion = :sessionVersion",
            "#createdAt = :createdAt",
            "#absoluteExpiresAt = :absoluteExpiresAt",
            "#csrfHash <> :csrfHash",
        ):
            self.assertIn(guard, condition)
        self.assertEqual(values[":subject"], "owner-123")
        self.assertEqual(values[":accountPurpose"], "client-owner")
        self.assertEqual(values[":cognitoUsername"], "owner@example.test")
        current_user_check = transaction[2]["ConditionCheck"]
        self.assertEqual(current_user_check["TableName"], session_v2.APPROVED_TABLE_NAME)
        for guard in (
            "#subject = :subject",
            "#accountPurpose = :accountPurpose",
            "#sessionVersion = :sessionVersion",
            "#enabled = :enabled",
        ):
            self.assertIn(guard, current_user_check["ConditionExpression"])

        with self.assertRaises(session_v2.AuthV2Unavailable):
            store.rotate_session(new_session["sessionIdHash"], new_session, now=NOW + 1)

    def test_release_throttle_is_idempotent_when_both_ttl_rows_are_absent(self):
        client = FakeLowLevelDynamo(get_responses=[{}, {}])
        store = InspectableDynamoAuthV2Store(client)
        reservation = {
            "mode": "reserved",
            "failureKeys": ["signin#account#a", "signin#ip#b"],
            "reservationId": "c" * 32,
            "windowSeconds": 900,
        }

        store.release_failure_attempt(reservation, now=NOW)

        self.assertEqual(
            [call for call in client.calls if call[0] == "transact_write_items"], []
        )

    def test_marshaller_rejects_non_string_map_keys(self):
        with self.assertRaises(session_v2.AuthV2Unavailable):
            session_v2.DynamoAuthV2Store._serialize({1: "value"})
        with self.assertRaises(session_v2.AuthV2Unavailable):
            session_v2.DynamoAuthV2Store._serialize_item({1: "value"})


if __name__ == "__main__":
    unittest.main()
