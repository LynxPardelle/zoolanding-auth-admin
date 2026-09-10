import copy
import hashlib
import inspect
import unittest
from decimal import Decimal
from unittest.mock import patch

import auth_admin_session_v2 as session_v2


NOW = 1_800_000_000


class FakeLowLevelDynamo:
    def __init__(
        self,
        *,
        get_responses=None,
        update_responses=None,
        transact_responses=None,
    ):
        self.calls = []
        self.get_responses = list(get_responses or [])
        self.update_responses = list(update_responses or [])
        self.transact_responses = list(transact_responses or [])

    @staticmethod
    def _result(outcomes):
        outcome = outcomes.pop(0) if outcomes else {}
        if isinstance(outcome, BaseException):
            raise outcome
        return copy.deepcopy(outcome)

    def put_item(self, **kwargs):
        self.calls.append(("put_item", copy.deepcopy(kwargs)))
        return {}

    def get_item(self, **kwargs):
        self.calls.append(("get_item", copy.deepcopy(kwargs)))
        return self._result(self.get_responses)

    def update_item(self, **kwargs):
        self.calls.append(("update_item", copy.deepcopy(kwargs)))
        return self._result(self.update_responses)

    def transact_write_items(self, **kwargs):
        self.calls.append(("transact_write_items", copy.deepcopy(kwargs)))
        return self._result(self.transact_responses)


class InspectableDynamoAuthV2Store(session_v2.DynamoAuthV2Store):
    """Exercise real store expressions without importing boto3 or calling AWS."""

    @staticmethod
    def _serialize(value):
        return {"fakeValue": copy.deepcopy(value)}

    @staticmethod
    def _deserialize(value):
        return copy.deepcopy(value["fakeValue"])


def encoded_item(**values):
    return {key: {"fakeValue": copy.deepcopy(value)} for key, value in values.items()}


def decoded_item(item):
    return {key: copy.deepcopy(value["fakeValue"]) for key, value in item.items()}


def sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DynamoAuthV2StoreContractTests(unittest.TestCase):
    def setUp(self):
        table_patch = patch.multiple(
            session_v2,
            SESSION_TABLE_NAME="thn-v2-session-test",
            CHALLENGE_TABLE_NAME="thn-v2-challenge-test",
            THROTTLE_TABLE_NAME="thn-v2-throttle-test",
        )
        table_patch.start()
        self.addCleanup(table_patch.stop)

    def test_narrow_marshaller_round_trips_supported_types_and_rejects_others(self):
        value = {
            "sessionVersion": 7,
            "enabled": True,
            "subject": "owner-123",
            "scope": {"environment": "test", "domain": "thehairnarrative.com"},
            "roles": ["owner", "editor"],
        }

        encoded = session_v2.DynamoAuthV2Store._serialize(value)
        decoded = session_v2.DynamoAuthV2Store._deserialize(encoded)
        session_item = session_v2.DynamoAuthV2Store._deserialize_item(
            session_v2.DynamoAuthV2Store._serialize_item(value)
        )

        self.assertEqual(decoded, value)
        self.assertEqual(session_item, value)
        self.assertIs(type(decoded["sessionVersion"]), int)
        self.assertIs(type(decoded["enabled"]), bool)
        for unsupported in (Decimal("1"), 1.5, object()):
            with self.subTest(unsupported=type(unsupported).__name__):
                with self.assertRaises(session_v2.AuthV2Unavailable):
                    session_v2.DynamoAuthV2Store._serialize(unsupported)
        for malformed in ({"N": "1.5"}, {"NULL": True}, {"unknown": "value"}):
            with self.subTest(malformed=malformed):
                with self.assertRaises(session_v2.AuthV2Unavailable):
                    session_v2.DynamoAuthV2Store._deserialize(malformed)

    def test_session_reads_touch_rotation_and_revocation_are_conditional(self):
        old_hash = "a" * 64
        new_hash = "b" * 64
        session = {
            "recordType": "authSessionV2",
            "sessionIdHash": old_hash,
            "csrfHash": "c" * 64,
            "sessionVersion": 3,
            "scope": copy.deepcopy(session_v2._SCOPE),
            "subject": "owner-123",
            "accountHash": "d" * 64,
            "accountPurpose": "client-owner",
            "cognitoUsername": "owner@example.test",
            "roles": ["journal-owner"],
            "createdAt": NOW,
            "lastSeenAt": NOW,
            "idleExpiresAt": NOW + 1_800,
            "absoluteExpiresAt": NOW + 43_200,
            "expiresAt": NOW + 43_200,
            "revokedAt": None,
        }
        touched = {**session, "lastSeenAt": NOW + 10, "idleExpiresAt": NOW + 1_810}
        client = FakeLowLevelDynamo(
            get_responses=[
                {"Item": encoded_item(**session)},
                {"Item": encoded_item(**touched)},
            ],
        )
        store = InspectableDynamoAuthV2Store(client)

        loaded = store.get_session(old_hash, consistent_read=True)
        refreshed = store.touch_session(
            old_hash,
            now=NOW + 10,
            idle_expires_at=NOW + 1_810,
            absolute_expires_at=NOW + 43_200,
            subject="owner-123",
            account_purpose="client-owner",
            session_version=3,
        )
        new_session = {**session, "sessionIdHash": new_hash}
        store.rotate_session(old_hash, new_session, now=NOW + 10)
        revoked = store.revoke_session(new_hash, now=NOW + 20)

        self.assertEqual(loaded, session)
        self.assertEqual(refreshed, touched)
        self.assertTrue(revoked)
        get_request = next(kwargs for name, kwargs in client.calls if name == "get_item")
        self.assertEqual(get_request["TableName"], "thn-v2-session-test")
        self.assertIs(get_request["ConsistentRead"], True)

        transactions = [
            kwargs["TransactItems"]
            for name, kwargs in client.calls
            if name == "transact_write_items"
        ]
        touch_request = transactions[0][0]["Update"]
        self.assertIn("attribute_not_exists(#revokedAt)", touch_request["ConditionExpression"])
        self.assertIn("#absoluteExpiresAt = :absolute", touch_request["ConditionExpression"])
        self.assertIn("#idleExpiresAt > :now", touch_request["ConditionExpression"])
        self.assertIn("#sessionVersion = :sessionVersion", touch_request["ConditionExpression"])
        self.assertEqual(
            touch_request["UpdateExpression"],
            "SET #lastSeenAt = :now, #idleExpiresAt = :idleExpiresAt",
        )

        transaction = transactions[1]
        self.assertEqual(len(transaction), 3)
        self.assertEqual(transaction[0]["Update"]["TableName"], "thn-v2-session-test")
        rotation_update = transaction[0]["Update"]
        for required_guard in (
            "attribute_exists(#sessionIdHash)",
            "attribute_not_exists(#revokedAt)",
            "#recordType = :recordType",
            "#scope = :scope",
            "#sessionVersion = :sessionVersion",
            "#idleExpiresAt > :now",
            "#absoluteExpiresAt > :now",
        ):
            self.assertIn(required_guard, rotation_update["ConditionExpression"])
        self.assertEqual(
            InspectableDynamoAuthV2Store._deserialize_item(
                rotation_update["ExpressionAttributeValues"]
            )[":scope"],
            session_v2._SCOPE,
        )
        self.assertEqual(transaction[1]["Put"]["TableName"], "thn-v2-session-test")
        self.assertEqual(
            transaction[1]["Put"]["ConditionExpression"],
            "attribute_not_exists(#sessionIdHash)",
        )
        self.assertEqual(
            transaction[2]["ConditionCheck"]["TableName"],
            session_v2.APPROVED_TABLE_NAME,
        )
        updates = [kwargs for name, kwargs in client.calls if name == "update_item"]
        revoke_request = updates[0]
        self.assertIn("attribute_exists(#sessionIdHash)", revoke_request["ConditionExpression"])
        self.assertIn("attribute_not_exists(#revokedAt)", revoke_request["ConditionExpression"])

    def test_ephemeral_claim_token_prevents_same_second_aba_and_guards_expiry(self):
        raw_claim_a = "a" * 32
        raw_claim_b = "b" * 32
        claimed_a = {
            "recordType": "authChallengeV2",
            "stateIdHash": "9" * 64,
            "csrfHash": "b" * 64,
            "scope": copy.deepcopy(session_v2._SCOPE),
            "accountHash": "c" * 64,
            "challengeName": "SOFTWARE_TOKEN_MFA",
            "createdAt": NOW,
            "expiresAt": NOW + 300,
            "claimedAt": NOW,
            "claimTokenHash": sha256(raw_claim_a),
            "cognitoSession": "private-session",
            "username": "private-user",
        }
        claimed_a["stateBindingHash"] = session_v2._ephemeral_state_binding_hash(
            claimed_a
        )
        claimed_b = {
            **claimed_a,
            "claimTokenHash": sha256(raw_claim_b),
        }
        client = FakeLowLevelDynamo(
            get_responses=[{"Item": encoded_item(**claimed_a)}],
            update_responses=[
                {"Attributes": encoded_item(**claimed_a)},
                {},
                {"Attributes": encoded_item(**claimed_b)},
                RuntimeError("ConditionalCheckFailedException"),
                RuntimeError("ConditionalCheckFailedException"),
                {},
            ],
        )
        store = InspectableDynamoAuthV2Store(client)

        loaded = store.get_ephemeral("9" * 64, consistent_read=True)
        with patch.object(
            session_v2.secrets,
            "token_urlsafe",
            side_effect=[raw_claim_a, raw_claim_b],
        ):
            acquired_a = store.claim_ephemeral(
                "9" * 64,
                expected_type="authChallengeV2",
                expected_binding_hash=claimed_a["stateBindingHash"],
                now=NOW,
            )
            self.assertIn("claimToken", acquired_a)
            self.assertEqual(acquired_a["claimToken"], raw_claim_a)
            self.assertIn(
                "claim_token",
                inspect.signature(store.release_ephemeral_claim).parameters,
            )
            self.assertIn(
                "claim_token",
                inspect.signature(store.consume_ephemeral_claim).parameters,
            )
            released_a = store.release_ephemeral_claim(
                "9" * 64,
                claim_token=raw_claim_a,
                expected_binding_hash=claimed_a["stateBindingHash"],
                now=NOW,
            )
            acquired_b = store.claim_ephemeral(
                "9" * 64,
                expected_type="authChallengeV2",
                expected_binding_hash=claimed_a["stateBindingHash"],
                now=NOW,
            )

        stale_release = store.release_ephemeral_claim(
            "9" * 64,
            claim_token=raw_claim_a,
            expected_binding_hash=claimed_a["stateBindingHash"],
            now=NOW,
        )
        expired_consume = store.consume_ephemeral_claim(
            "9" * 64,
            claim_token=raw_claim_b,
            expected_binding_hash=claimed_a["stateBindingHash"],
            now=NOW + 300,
        )
        consumed_b = store.consume_ephemeral_claim(
            "9" * 64,
            claim_token=raw_claim_b,
            expected_binding_hash=claimed_a["stateBindingHash"],
            now=NOW + 1,
        )

        self.assertEqual(loaded, claimed_a)
        self.assertEqual(acquired_b["claimToken"], raw_claim_b)
        self.assertNotEqual(acquired_a["claimToken"], acquired_b["claimToken"])
        self.assertTrue(released_a)
        self.assertFalse(stale_release)
        self.assertFalse(expired_consume)
        self.assertTrue(consumed_b)
        get_request = next(kwargs for name, kwargs in client.calls if name == "get_item")
        self.assertEqual(get_request["TableName"], "thn-v2-challenge-test")
        self.assertIs(get_request["ConsistentRead"], True)
        updates = [kwargs for name, kwargs in client.calls if name == "update_item"]
        claim_a, release_a, claim_b, stale_release_a, expired_b, consume_b = updates
        for claim_request, raw_claim in (
            (claim_a, raw_claim_a),
            (claim_b, raw_claim_b),
        ):
            self.assertIn("#recordType = :recordType", claim_request["ConditionExpression"])
            self.assertIn("#expiresAt > :now", claim_request["ConditionExpression"])
            self.assertIn("attribute_not_exists(#claimedAt)", claim_request["ConditionExpression"])
            self.assertIn("#claimTokenHash = :claimTokenHash", claim_request["UpdateExpression"])
            values = decoded_item(claim_request["ExpressionAttributeValues"])
            self.assertEqual(values[":claimTokenHash"], sha256(raw_claim))
            self.assertNotIn(raw_claim, repr(claim_request))
        for release_request in (release_a, stale_release_a):
            self.assertIn("#claimTokenHash = :claimTokenHash", release_request["ConditionExpression"])
            self.assertIn("attribute_not_exists(#consumedAt)", release_request["ConditionExpression"])
            self.assertIn("#claimTokenHash", release_request["UpdateExpression"])
        self.assertEqual(
            decoded_item(stale_release_a["ExpressionAttributeValues"])[":claimTokenHash"],
            sha256(raw_claim_a),
        )
        self.assertIn("#claimTokenHash = :claimTokenHash", expired_b["ConditionExpression"])
        self.assertIn("#expiresAt > :now", expired_b["ConditionExpression"])
        self.assertEqual(
            decoded_item(expired_b["ExpressionAttributeValues"])[":now"],
            NOW + 300,
        )
        self.assertIn("#expiresAt > :now", consume_b["ConditionExpression"])
        self.assertEqual(
            decoded_item(consume_b["ExpressionAttributeValues"])[":claimTokenHash"],
            sha256(raw_claim_b),
        )

    def test_failure_capacity_uses_exact_rolling_events_and_hashed_reservation(self):
        boundary_event = {"eventIdHash": sha256("boundary"), "occurredAt": NOW - 900}
        account_recent = [
            {"eventIdHash": sha256(f"account-{index}"), "occurredAt": NOW - 899 + index}
            for index in range(4)
        ]
        ip_recent = [
            {"eventIdHash": sha256(f"ip-{index}"), "occurredAt": NOW - 899 + index}
            for index in range(4)
        ]
        account = {
            "failureKey": "signin#account#account-hash",
            "recordType": "authFailureWindowV2",
            "events": [boundary_event, *account_recent],
            "version": 7,
        }
        source_ip = {
            "failureKey": "signin#ip#ip-hash",
            "recordType": "authFailureWindowV2",
            "events": [boundary_event, *ip_recent],
            "version": 11,
        }
        client = FakeLowLevelDynamo(
            get_responses=[
                {"Item": encoded_item(**account)},
                {"Item": encoded_item(**source_ip)},
            ]
        )
        store = InspectableDynamoAuthV2Store(client)

        reservation = store.reserve_failure_attempt(
            "signin",
            "account-hash",
            "ip-hash",
            now=NOW,
            window_seconds=900,
            account_limit=5,
            ip_limit=5,
        )

        gets = [kwargs for name, kwargs in client.calls if name == "get_item"]
        self.assertEqual(len(gets), 2)
        self.assertTrue(all(call["ConsistentRead"] is True for call in gets))
        self.assertTrue(all(call["TableName"] == "thn-v2-throttle-test" for call in gets))
        self.assertEqual(
            [decoded_item(call["Key"])["failureKey"] for call in gets],
            ["signin#account#account-hash", "signin#ip#ip-hash"],
        )

        transaction_calls = [
            kwargs for name, kwargs in client.calls if name == "transact_write_items"
        ]
        self.assertEqual(len(transaction_calls), 1)
        reserve_transaction = transaction_calls[0]
        writes = reserve_transaction["TransactItems"]
        self.assertEqual(len(writes), 2)
        next_items = [decoded_item(write["Put"]["Item"]) for write in writes]
        self.assertIn("reservationId", reservation)
        event_id_hash = sha256(reservation["reservationId"])
        for item, recent in zip(next_items, (account_recent, ip_recent)):
            self.assertEqual(item["events"], [*recent, {"eventIdHash": event_id_hash, "occurredAt": NOW}])
            self.assertEqual(item["failureCount"], 5)
            self.assertNotIn(boundary_event, item["events"])
            self.assertNotIn(reservation["reservationId"], repr(item))
        self.assertEqual([item["version"] for item in next_items], [8, 12])
        self.assertEqual(
            [write["Put"]["ConditionExpression"] for write in writes],
            ["#version = :expectedVersion", "#version = :expectedVersion"],
        )
        expected_versions = [
            decoded_item(write["Put"]["ExpressionAttributeValues"])[":expectedVersion"]
            for write in writes
        ]
        self.assertEqual(expected_versions, [7, 11])
        self.assertEqual(len(reserve_transaction["ClientRequestToken"]), 32)

        client.get_responses.extend(
            [{"Item": write["Put"]["Item"]} for write in writes]
        )
        with self.assertRaises(session_v2.AuthV2Throttled):
            store.reserve_failure_attempt(
                "signin",
                "account-hash",
                "ip-hash",
                now=NOW,
                window_seconds=900,
                account_limit=5,
                ip_limit=5,
            )
        self.assertEqual(
            len([call for call in client.calls if call[0] == "transact_write_items"]),
            1,
        )

    def test_failure_release_is_exact_cas_and_idempotent(self):
        reservation_id = "c" * 32
        reserved_hash = sha256(reservation_id)
        account_other = {"eventIdHash": sha256("account-other"), "occurredAt": NOW - 10}
        ip_other = {"eventIdHash": sha256("ip-other"), "occurredAt": NOW - 9}
        records = [
            {
                "failureKey": "signin#account#account-hash",
                "recordType": "authFailureWindowV2",
                "events": [account_other, {"eventIdHash": reserved_hash, "occurredAt": NOW}],
                "version": 8,
            },
            {
                "failureKey": "signin#ip#ip-hash",
                "recordType": "authFailureWindowV2",
                "events": [ip_other, {"eventIdHash": reserved_hash, "occurredAt": NOW}],
                "version": 12,
            },
        ]
        client = FakeLowLevelDynamo(
            get_responses=[{"Item": encoded_item(**record)} for record in records]
        )
        store = InspectableDynamoAuthV2Store(client)
        reservation = {
            "mode": "reserved",
            "failureKeys": [record["failureKey"] for record in records],
            "reservationId": reservation_id,
            "windowSeconds": 900,
        }

        store.release_failure_attempt(reservation, now=NOW + 1)

        gets = [kwargs for name, kwargs in client.calls if name == "get_item"]
        self.assertEqual(len(gets), 2)
        self.assertTrue(all(request["ConsistentRead"] is True for request in gets))
        release_transaction = next(
            kwargs for name, kwargs in client.calls if name == "transact_write_items"
        )
        release_writes = release_transaction["TransactItems"]
        self.assertEqual(len(release_writes), 2)
        released_items = [decoded_item(write["Put"]["Item"]) for write in release_writes]
        self.assertEqual(
            [item["events"] for item in released_items],
            [[account_other], [ip_other]],
        )
        self.assertTrue(
            all(
                write["Put"]["ConditionExpression"] == "#version = :expectedVersion"
                for write in release_writes
            )
        )
        self.assertNotIn(reservation_id, repr(release_writes))

        client.get_responses.extend(
            [{"Item": write["Put"]["Item"]} for write in release_writes]
        )
        store.release_failure_attempt(reservation, now=NOW + 2)
        self.assertEqual(
            len([call for call in client.calls if call[0] == "transact_write_items"]),
            1,
        )


if __name__ == "__main__":
    unittest.main()
