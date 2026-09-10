import copy
import unittest
from unittest.mock import patch

import auth_admin_session_v2 as session_v2


NOW = 1_800_000_000


class CapturingDynamo:
    def __init__(self):
        self.transaction = None

    def transact_write_items(self, **kwargs):
        self.transaction = copy.deepcopy(kwargs)
        return {}


class DynamoAuthV2SessionRotationContractTests(unittest.TestCase):
    def setUp(self):
        table_patch = patch.object(
            session_v2, "SESSION_TABLE_NAME", "thn-v2-session-test"
        )
        table_patch.start()
        self.addCleanup(table_patch.stop)

    def _old_session_update(self):
        client = CapturingDynamo()
        store = session_v2.DynamoAuthV2Store(client)
        absolute = NOW + session_v2.SESSION_ABSOLUTE_SECONDS
        store.rotate_session(
            "a" * 64,
            {
                "recordType": "authSessionV2",
                "sessionIdHash": "b" * 64,
                "csrfHash": "c" * 64,
                "scope": copy.deepcopy(session_v2._SCOPE),
                "subject": "owner-123",
                "accountHash": "d" * 64,
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
            },
            now=NOW,
        )
        self.assertIsNotNone(client.transaction)
        return client.transaction["TransactItems"][0]["Update"]

    @staticmethod
    def _decoded_values(update):
        return session_v2.DynamoAuthV2Store._deserialize_item(
            update["ExpressionAttributeValues"]
        )

    def test_rotation_requires_the_old_session_to_exist_and_be_unrevoked(self):
        update = self._old_session_update()

        condition = update["ConditionExpression"]
        names = update["ExpressionAttributeNames"]
        self.assertIn("attribute_exists(#sessionIdHash)", condition)
        self.assertIn("attribute_not_exists(#revokedAt)", condition)
        self.assertEqual(names["#sessionIdHash"], "sessionIdHash")
        self.assertEqual(names["#revokedAt"], "revokedAt")

    def test_rotation_requires_the_exact_v2_record_type_and_scope(self):
        update = self._old_session_update()

        condition = update["ConditionExpression"]
        names = update["ExpressionAttributeNames"]
        values = self._decoded_values(update)
        self.assertIn("#recordType = :recordType", condition)
        self.assertIn("#scope = :scope", condition)
        self.assertEqual(names["#recordType"], "recordType")
        self.assertEqual(names["#scope"], "scope")
        self.assertEqual(values[":recordType"], "authSessionV2")
        self.assertEqual(values[":scope"], session_v2._SCOPE)

    def test_rotation_requires_the_expected_session_version(self):
        update = self._old_session_update()

        condition = update["ConditionExpression"]
        names = update["ExpressionAttributeNames"]
        values = self._decoded_values(update)
        self.assertIn("#sessionVersion = :sessionVersion", condition)
        self.assertEqual(names["#sessionVersion"], "sessionVersion")
        self.assertEqual(values[":sessionVersion"], 7)

    def test_rotation_binds_the_same_signed_cognito_username(self):
        update = self._old_session_update()

        condition = update["ConditionExpression"]
        names = update["ExpressionAttributeNames"]
        values = self._decoded_values(update)
        self.assertIn("#cognitoUsername = :cognitoUsername", condition)
        self.assertEqual(names["#cognitoUsername"], "cognitoUsername")
        self.assertEqual(values[":cognitoUsername"], "owner@example.test")

    def test_rotation_requires_idle_and_absolute_expiry_to_be_in_the_future(self):
        update = self._old_session_update()

        condition = update["ConditionExpression"]
        names = update["ExpressionAttributeNames"]
        values = self._decoded_values(update)
        self.assertIn("#idleExpiresAt > :now", condition)
        self.assertIn("#absoluteExpiresAt > :now", condition)
        self.assertEqual(names["#idleExpiresAt"], "idleExpiresAt")
        self.assertEqual(names["#absoluteExpiresAt"], "absoluteExpiresAt")
        self.assertEqual(values[":now"], NOW)


if __name__ == "__main__":
    unittest.main()
