import copy
import inspect
from pathlib import Path
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


def state(
    *,
    subject="owner-123",
    account_purpose="client-owner",
    session_version=1,
    enabled=False,
    **overrides,
):
    value = {
        "contractVersion": 1,
        "scope": copy.deepcopy(SCOPE),
        "subject": subject,
        "accountPurpose": account_purpose,
        "sessionVersion": session_version,
        "enabled": enabled,
    }
    value.update(overrides)
    return value


def storage_item(value):
    return {
        "pk": PARTITION_KEY,
        "sk": f"SUBJECT#{value['subject']}",
        **copy.deepcopy(value),
    }


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


class FakeDynamoClient:
    def __init__(self, items=None, provider_error=None):
        self.items = {}
        for value in items or []:
            raw = storage_item(value)
            self.items[(raw["pk"], raw["sk"])] = raw
        self.provider_error = provider_error
        self.calls = []

    def _raise_provider_error(self):
        if self.provider_error is not None:
            raise self.provider_error

    def put_item(self, **kwargs):
        self.calls.append(("put_item", copy.deepcopy(kwargs)))
        self._raise_provider_error()
        raw = unmarshal_item(kwargs["Item"])
        key = (raw["pk"], raw["sk"])
        if key in self.items:
            raise RuntimeError("ConditionalCheckFailedException: private duplicate")
        self.items[key] = raw
        return {}

    def get_item(self, **kwargs):
        self.calls.append(("get_item", copy.deepcopy(kwargs)))
        self._raise_provider_error()
        raw_key = unmarshal_item(kwargs["Key"])
        value = self.items.get((raw_key["pk"], raw_key["sk"]))
        return {"Item": marshal_item(value)} if value is not None else {}

    def update_item(self, **kwargs):
        self.calls.append(("update_item", copy.deepcopy(kwargs)))
        self._raise_provider_error()
        raw_key = unmarshal_item(kwargs["Key"])
        values = {
            key: unmarshal_value(value)
            for key, value in kwargs["ExpressionAttributeValues"].items()
        }
        item = self.items.get((raw_key["pk"], raw_key["sk"]))
        if (
            item is None
            or item["accountPurpose"] != values[":expectedPurpose"]
            or item["sessionVersion"] != values[":expectedVersion"]
            or item["enabled"] is not values[":expectedEnabled"]
        ):
            raise RuntimeError("ConditionalCheckFailedException: private stale state")
        item["enabled"] = values[":disabled"]
        item["sessionVersion"] = values[":nextVersion"]
        return {"Attributes": marshal_item(item)}


class AuthAdminCurrentUserV2ContractTests(unittest.TestCase):
    def assert_safe_error(self, callable_):
        with self.assertRaises(current_user.CurrentUserStateUnavailable) as caught:
            callable_()
        self.assertEqual(str(caught.exception), "current user state is unavailable")
        self.assertNotIn("private", str(caught.exception))

    def test_provisions_exact_disabled_state_once_for_each_allowed_purpose(self):
        for purpose in ("qa", "client-owner"):
            with self.subTest(purpose=purpose):
                client = FakeDynamoClient()

                result = current_user.provision_current_user_state(
                    client,
                    scope=SCOPE,
                    subject=f"{purpose}-subject",
                    account_purpose=purpose,
                )

                expected = state(subject=f"{purpose}-subject", account_purpose=purpose)
                self.assertEqual(result, expected)
                self.assertIsNot(result, expected)
                operation, request = client.calls[0]
                self.assertEqual(operation, "put_item")
                self.assertEqual(request["TableName"], TABLE_NAME)
                self.assertEqual(unmarshal_item(request["Item"]), storage_item(expected))
                self.assertEqual(
                    request["ConditionExpression"],
                    "attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
                )
                self.assertEqual(request["ExpressionAttributeNames"], {"#pk": "pk", "#sk": "sk"})
                self.assertEqual(request["ReturnValues"], "NONE")
                self.assertEqual(request["ReturnValuesOnConditionCheckFailure"], "NONE")

    def test_provision_is_create_only_and_duplicate_error_is_sanitized(self):
        original = state()
        client = FakeDynamoClient([original])

        self.assert_safe_error(
            lambda: current_user.provision_current_user_state(
                client,
                scope=SCOPE,
                subject="owner-123",
                account_purpose="qa",
            )
        )

        self.assertEqual(client.items[(PARTITION_KEY, "SUBJECT#owner-123")], storage_item(original))
        self.assertEqual([name for name, _ in client.calls], ["put_item"])

    def test_provision_rejects_invalid_scope_subject_or_purpose_before_storage(self):
        cases = (
            {"scope": {**SCOPE, "environment": "prod"}},
            {"scope": {**SCOPE, "unknown": "value"}},
            {"subject": ""},
            {"subject": "subject/with/path"},
            {"account_purpose": "administrator"},
            {"account_purpose": []},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                client = FakeDynamoClient()
                arguments = {
                    "scope": SCOPE,
                    "subject": "owner-123",
                    "account_purpose": "client-owner",
                }
                arguments.update(overrides)
                self.assert_safe_error(
                    lambda: current_user.provision_current_user_state(client, **arguments)
                )
                self.assertEqual(client.calls, [])

    def test_load_uses_exact_key_and_strongly_consistent_read(self):
        expected = state(enabled=True, session_version=4)
        client = FakeDynamoClient([expected])

        result = current_user.load_current_user_state(
            client,
            scope=SCOPE,
            subject="owner-123",
        )

        self.assertEqual(result, expected)
        self.assertEqual(
            client.calls,
            [
                (
                    "get_item",
                    {
                        "TableName": TABLE_NAME,
                        "Key": marshal_item(
                            {"pk": PARTITION_KEY, "sk": "SUBJECT#owner-123"}
                        ),
                        "ConsistentRead": True,
                    },
                )
            ],
        )

    def test_load_rejects_missing_malformed_or_nonexact_state_with_one_safe_error(self):
        malformed_states = (
            state(contractVersion=2),
            state(scope={**SCOPE, "domain": "other.example"}),
            state(sessionVersion=True),
            state(enabled="true"),
            state(accountPurpose="administrator"),
            state(unexpected="private-state-sentinel"),
        )
        for malformed in malformed_states:
            with self.subTest(malformed=malformed):
                client = FakeDynamoClient([state()])
                client.items[(PARTITION_KEY, "SUBJECT#owner-123")] = storage_item(malformed)
                self.assert_safe_error(
                    lambda: current_user.load_current_user_state(
                        client,
                        scope=SCOPE,
                        subject="owner-123",
                    )
                )

        self.assert_safe_error(
            lambda: current_user.load_current_user_state(
                FakeDynamoClient(),
                scope=SCOPE,
                subject="missing-subject",
            )
        )
        self.assert_safe_error(
            lambda: current_user.load_current_user_state(
                FakeDynamoClient(provider_error=RuntimeError("private provider sentinel")),
                scope=SCOPE,
                subject="owner-123",
            )
        )

    def test_disable_is_a_purpose_version_enabled_cas_and_preserves_purpose(self):
        client = FakeDynamoClient(
            [state(account_purpose="client-owner", session_version=7, enabled=True)]
        )

        result = current_user.disable_current_user_state(
            client,
            scope=SCOPE,
            subject="owner-123",
            account_purpose="client-owner",
            session_version=7,
        )

        self.assertEqual(
            result,
            state(account_purpose="client-owner", session_version=8, enabled=False),
        )
        self.assertEqual([name for name, _ in client.calls], ["get_item", "update_item"])
        request = client.calls[1][1]
        self.assertEqual(request["TableName"], TABLE_NAME)
        self.assertEqual(
            request["ConditionExpression"],
            "#accountPurpose = :expectedPurpose AND #sessionVersion = :expectedVersion "
            "AND #enabled = :expectedEnabled",
        )
        self.assertEqual(
            request["UpdateExpression"],
            "SET #enabled = :disabled, #sessionVersion = :nextVersion",
        )
        self.assertEqual(
            request["ExpressionAttributeNames"],
            {
                "#accountPurpose": "accountPurpose",
                "#sessionVersion": "sessionVersion",
                "#enabled": "enabled",
            },
        )
        self.assertEqual(
            {
                key: unmarshal_value(value)
                for key, value in request["ExpressionAttributeValues"].items()
            },
            {
                ":expectedPurpose": "client-owner",
                ":expectedVersion": 7,
                ":expectedEnabled": True,
                ":disabled": False,
                ":nextVersion": 8,
            },
        )
        self.assertEqual(request["ReturnValues"], "ALL_NEW")
        self.assertEqual(request["ReturnValuesOnConditionCheckFailure"], "NONE")

    def test_stale_disable_retry_fails_without_a_second_increment(self):
        client = FakeDynamoClient([state(session_version=5, enabled=True)])
        current_user.disable_current_user_state(
            client,
            scope=SCOPE,
            subject="owner-123",
            account_purpose="client-owner",
            session_version=5,
        )

        self.assert_safe_error(
            lambda: current_user.disable_current_user_state(
                client,
                scope=SCOPE,
                subject="owner-123",
                account_purpose="client-owner",
                session_version=5,
            )
        )

        persisted = client.items[(PARTITION_KEY, "SUBJECT#owner-123")]
        self.assertEqual(persisted["sessionVersion"], 6)
        self.assertIs(persisted["enabled"], False)
        self.assertEqual([name for name, _ in client.calls].count("update_item"), 1)

    def test_disable_rejects_wrong_purpose_version_or_inactive_state_before_update(self):
        cases = (
            (state(enabled=True), "qa", 1),
            (state(enabled=True, session_version=4), "client-owner", 3),
            (state(enabled=False, session_version=4), "client-owner", 4),
        )
        for existing, purpose, version in cases:
            with self.subTest(existing=existing, purpose=purpose, version=version):
                client = FakeDynamoClient([existing])
                self.assert_safe_error(
                    lambda: current_user.disable_current_user_state(
                        client,
                        scope=SCOPE,
                        subject="owner-123",
                        account_purpose=purpose,
                        session_version=version,
                    )
                )
                self.assertEqual([name for name, _ in client.calls], ["get_item"])

    def test_assert_session_current_requires_explicit_scope_subject_purpose_and_version(self):
        signature = inspect.signature(current_user.assert_session_current)
        for name in ("scope", "subject", "account_purpose", "session_version"):
            self.assertIn(name, signature.parameters)
            self.assertIs(signature.parameters[name].default, inspect.Parameter.empty)

        active = state(enabled=True, session_version=9)
        client = FakeDynamoClient([active])
        result = current_user.assert_session_current(
            client,
            scope=SCOPE,
            subject="owner-123",
            account_purpose="client-owner",
            session_version=9,
        )
        self.assertEqual(result, active)
        self.assertTrue(client.calls[0][1]["ConsistentRead"])

    def test_assert_session_current_fails_closed_for_stale_wrong_purpose_or_disabled(self):
        cases = (
            (state(enabled=True, session_version=3), "client-owner", 2),
            (state(enabled=True, account_purpose="qa"), "client-owner", 1),
            (state(enabled=False), "client-owner", 1),
        )
        for existing, purpose, version in cases:
            with self.subTest(existing=existing, purpose=purpose, version=version):
                client = FakeDynamoClient([existing])
                self.assert_safe_error(
                    lambda: current_user.assert_session_current(
                        client,
                        scope=SCOPE,
                        subject="owner-123",
                        account_purpose=purpose,
                        session_version=version,
                    )
                )
                self.assertEqual([name for name, _ in client.calls], ["get_item"])

    def test_contract_has_no_account_purpose_change_api_and_is_not_wired_into_v1(self):
        forbidden_names = {
            "change_account_purpose",
            "set_account_purpose",
            "update_account_purpose",
        }
        self.assertTrue(forbidden_names.isdisjoint(set(current_user.__all__)))
        source = Path(current_user.__file__).with_name("lambda_function.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("auth_admin_current_user_v2", source)

    def test_code_owned_scope_constant_cannot_be_mutated(self):
        self.assertFalse(hasattr(current_user.APPROVED_SCOPE, "__setitem__"))


if __name__ == "__main__":
    unittest.main()
