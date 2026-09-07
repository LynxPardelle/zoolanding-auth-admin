import copy
import unittest

import auth_admin_current_user_v2 as current_user


SCOPE = {
    "environment": "test",
    "domain": "thehairnarrative.com",
    "tenantId": "thehairnarrative-com",
    "hubId": "thehairnarrative-com-journal",
    "authProfileId": "journal-owner",
    "serviceBindingId": "thn-journal-test-v2",
}
TABLE_NAME = "zoolanding-auth-admin-test-ThnCurrentUserStateV2"
PARTITION_KEY = "CURRENT_USER#test#thn-journal-test-v2"
OWNER_SORT_KEY = "OWNER#client-owner"


def state(*, subject="owner-123", session_version=1, enabled=False):
    return {
        "contractVersion": 1,
        "scope": copy.deepcopy(SCOPE),
        "subject": subject,
        "accountPurpose": "client-owner",
        "sessionVersion": session_version,
        "enabled": enabled,
    }


def binding(*, subject="owner-123", **overrides):
    value = {
        "contractVersion": 1,
        "scope": copy.deepcopy(SCOPE),
        "subject": subject,
        "accountPurpose": "client-owner",
    }
    value.update(overrides)
    return value


def marshal_value(value):
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, int):
        return {"N": str(value)}
    if isinstance(value, dict):
        return {"M": {key: marshal_value(item) for key, item in value.items()}}
    raise AssertionError(f"unsupported fixture value: {type(value)!r}")


def marshal_item(value):
    return {key: marshal_value(item) for key, item in value.items()}


def unmarshal_value(value):
    if set(value) == {"S"}:
        return value["S"]
    if set(value) == {"N"}:
        return int(value["N"])
    if set(value) == {"BOOL"}:
        return value["BOOL"]
    if set(value) == {"M"}:
        return {key: unmarshal_value(item) for key, item in value["M"].items()}
    raise AssertionError(f"unsupported attribute value: {value!r}")


def unmarshal_item(value):
    return {key: unmarshal_value(item) for key, item in value.items()}


class TransactionalFakeDynamoClient:
    def __init__(self, *, binding_item=None, current_state=None, commit_then_error=False):
        self.items = {}
        self.calls = []
        self.commit_then_error = commit_then_error
        if binding_item is not None:
            self._store({
                "pk": PARTITION_KEY,
                "sk": OWNER_SORT_KEY,
                **copy.deepcopy(binding_item),
            })
        if current_state is not None:
            self._store({
                "pk": PARTITION_KEY,
                "sk": f"SUBJECT#{current_state['subject']}",
                **copy.deepcopy(current_state),
            })

    def _store(self, item):
        self.items[(item["pk"], item["sk"])] = item

    def transact_write_items(self, **kwargs):
        self.calls.append(("transact_write_items", copy.deepcopy(kwargs)))
        pending = [unmarshal_item(entry["Put"]["Item"]) for entry in kwargs["TransactItems"]]
        keys = [(item["pk"], item["sk"]) for item in pending]
        if len(set(keys)) != len(keys) or any(key in self.items for key in keys):
            raise RuntimeError("ConditionalCheckFailedException: private duplicate")
        for item in pending:
            self._store(item)
        if self.commit_then_error:
            raise RuntimeError("private response lost after commit")
        return {}

    def get_item(self, **kwargs):
        self.calls.append(("get_item", copy.deepcopy(kwargs)))
        raw_key = unmarshal_item(kwargs["Key"])
        item = self.items.get((raw_key["pk"], raw_key["sk"]))
        return {"Item": marshal_item(item)} if item is not None else {}


class SingleOwnerStateTests(unittest.TestCase):
    def assert_safe_error(self, callable_):
        with self.assertRaises(current_user.CurrentUserStateUnavailable) as caught:
            callable_()
        self.assertEqual(str(caught.exception), "current user state is unavailable")

    def test_provision_reserves_single_owner_and_current_state_atomically(self):
        client = TransactionalFakeDynamoClient()

        result = current_user.provision_single_owner_state(
            client,
            scope=SCOPE,
            subject="owner-123",
            account_purpose="client-owner",
        )

        self.assertEqual(result, state())
        self.assertEqual([name for name, _ in client.calls], ["transact_write_items"])
        request = client.calls[0][1]
        self.assertEqual(request["ReturnConsumedCapacity"], "NONE")
        self.assertEqual(request["ReturnItemCollectionMetrics"], "NONE")
        self.assertEqual(len(request["TransactItems"]), 2)
        stored = [unmarshal_item(item["Put"]["Item"]) for item in request["TransactItems"]]
        self.assertEqual(
            stored,
            [
                {"pk": PARTITION_KEY, "sk": OWNER_SORT_KEY, **binding()},
                {"pk": PARTITION_KEY, "sk": "SUBJECT#owner-123", **state()},
            ],
        )
        for item in request["TransactItems"]:
            put = item["Put"]
            self.assertEqual(put["TableName"], TABLE_NAME)
            self.assertEqual(
                put["ConditionExpression"],
                "attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
            )
            self.assertEqual(put["ExpressionAttributeNames"], {"#pk": "pk", "#sk": "sk"})
            self.assertEqual(put["ReturnValuesOnConditionCheckFailure"], "NONE")

    def test_load_binding_uses_exact_key_and_strong_consistency(self):
        client = TransactionalFakeDynamoClient(binding_item=binding())

        result = current_user.load_single_owner_binding(client, scope=SCOPE)

        self.assertEqual(result, binding())
        self.assertEqual(
            client.calls,
            [
                (
                    "get_item",
                    {
                        "TableName": TABLE_NAME,
                        "Key": marshal_item({"pk": PARTITION_KEY, "sk": OWNER_SORT_KEY}),
                        "ConsistentRead": True,
                    },
                )
            ],
        )

    def test_lost_transaction_response_reconciles_exact_committed_state(self):
        client = TransactionalFakeDynamoClient(commit_then_error=True)

        result = current_user.provision_single_owner_state(
            client,
            scope=SCOPE,
            subject="owner-123",
            account_purpose="client-owner",
        )

        self.assertEqual(result, state())
        self.assertEqual(
            [name for name, _ in client.calls],
            ["transact_write_items", "get_item", "get_item"],
        )

    def test_exact_duplicate_is_idempotently_reconciled(self):
        client = TransactionalFakeDynamoClient(
            binding_item=binding(),
            current_state=state(),
        )

        result = current_user.provision_single_owner_state(
            client,
            scope=SCOPE,
            subject="owner-123",
            account_purpose="client-owner",
        )

        self.assertEqual(result, state())

    def test_existing_other_owner_is_rejected_without_new_state(self):
        client = TransactionalFakeDynamoClient(
            binding_item=binding(subject="other-owner"),
            current_state=state(subject="other-owner"),
        )

        self.assert_safe_error(
            lambda: current_user.provision_single_owner_state(
                client,
                scope=SCOPE,
                subject="owner-123",
                account_purpose="client-owner",
            )
        )

        self.assertNotIn((PARTITION_KEY, "SUBJECT#owner-123"), client.items)

    def test_existing_owner_with_changed_state_is_not_treated_as_initial_provision(self):
        client = TransactionalFakeDynamoClient(
            binding_item=binding(),
            current_state=state(session_version=2, enabled=True),
        )

        self.assert_safe_error(
            lambda: current_user.provision_single_owner_state(
                client,
                scope=SCOPE,
                subject="owner-123",
                account_purpose="client-owner",
            )
        )

    def test_single_owner_provision_rejects_other_purpose_before_storage(self):
        client = TransactionalFakeDynamoClient()

        self.assert_safe_error(
            lambda: current_user.provision_single_owner_state(
                client,
                scope=SCOPE,
                subject="owner-123",
                account_purpose="qa",
            )
        )

        self.assertEqual(client.calls, [])

    def test_load_rejects_malformed_or_missing_binding(self):
        for malformed in (
            binding(accountPurpose="qa"),
            binding(contractVersion=2),
            binding(unexpected="private"),
            binding(scope={**SCOPE, "domain": "other.example"}),
        ):
            with self.subTest(malformed=malformed):
                self.assert_safe_error(
                    lambda: current_user.load_single_owner_binding(
                        TransactionalFakeDynamoClient(binding_item=malformed),
                        scope=SCOPE,
                    )
                )

        self.assert_safe_error(
            lambda: current_user.load_single_owner_binding(
                TransactionalFakeDynamoClient(),
                scope=SCOPE,
            )
        )


if __name__ == "__main__":
    unittest.main()
