import copy
import unittest

import service_binding_registry_consumer_v2 as consumer


TABLE_NAME = "zoolanding-content-hub-test-ServiceBindingRegistryV2"
EXPECTED_DESCRIPTOR = {
    "descriptorVersionId": "test-v1",
    "descriptorSha256": "a" * 64,
    "authPolicyVersion": "journal-owner-v1",
}
TRUSTED_RESOURCE_SCOPE = {
    "partition": "aws",
    "accountId": "123456789012",
    "region": "us-east-1",
}


def active_record(**overrides):
    record = {
        "pk": "SERVICE_BINDING#test#thn-journal-test-v2",
        "sk": "REGISTRY#V2",
        "recordType": "service-binding-registry-v2",
        "schemaVersion": 2,
        "environment": "test",
        "domain": "thehairnarrative.com",
        "serviceBindingId": "thn-journal-test-v2",
        "descriptorVersionId": "test-v1",
        "descriptorSha256": "a" * 64,
        "registryRevision": 7,
        "activationStatus": "active",
        "writerMode": "disabled",
        "writerEpoch": 3,
        "hubId": "thehairnarrative-com-journal",
        "tenantId": "thehairnarrative-com",
        "cookieNamespace": "endefiz7dkk635k6di6k",
        "authProfileId": "journal-owner",
        "authPolicyVersion": "journal-owner-v1",
        "adminOrigin": "https://admin-test.thehairnarrative.com",
        "resourceBindings": {
            "authoringFunctionArn": (
                "arn:aws:lambda:us-east-1:123456789012:function:"
                "zoolanding-content-hub-test-ThnContentHubV2Authoring"
            ),
            "metadataTableArn": (
                "arn:aws:dynamodb:us-east-1:123456789012:table/"
                "zoolanding-content-hub-test-ThnContentHubV2Metadata"
            ),
        },
        "reservationOwner": {
            "environment": "test",
            "domain": "thehairnarrative.com",
            "serviceBindingId": "thn-journal-test-v2",
            "hubId": "thehairnarrative-com-journal",
            "tenantId": "thehairnarrative-com",
            "authProfileId": "journal-owner",
        },
    }
    record.update(overrides)
    return record


class FakeDynamoClient:
    def __init__(self, response, error=None):
        self.response = copy.deepcopy(response)
        self.error = error
        if "Item" in self.response and isinstance(self.response["Item"], dict):
            self.response["Item"] = _marshal_item(self.response["Item"])
        if "Items" in self.response and isinstance(self.response["Items"], list):
            self.response["Items"] = [
                _marshal_item(item) if isinstance(item, dict) else item
                for item in self.response["Items"]
            ]
        self.calls = []

    def get_item(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        if self.error:
            raise self.error
        return copy.deepcopy(self.response)


def _marshal_value(value):
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, int):
        return {"N": str(value)}
    if isinstance(value, dict):
        return {"M": {key: _marshal_value(item) for key, item in value.items()}}
    raise AssertionError(f"unsupported fixture value: {type(value)!r}")


def _marshal_item(item):
    return {key: _marshal_value(value) for key, value in item.items()}


def load(client, **overrides):
    arguments = {
        "expected_descriptor": EXPECTED_DESCRIPTOR,
        "expected_registry_revision": 7,
        "trusted_resource_scope": TRUSTED_RESOURCE_SCOPE,
    }
    arguments.update(overrides)
    return consumer.load_active_service_binding(client, **arguments)


class ServiceBindingRegistryConsumerV2Tests(unittest.TestCase):
    def test_loads_one_active_record_by_exact_strongly_consistent_key(self):
        client = FakeDynamoClient({"Item": active_record()})

        result = load(client)

        self.assertEqual(result, active_record())
        self.assertIsNot(result, client.response["Item"])
        self.assertEqual(
            client.calls,
            [
                {
                    "TableName": TABLE_NAME,
                    "Key": {
                        "pk": {"S": "SERVICE_BINDING#test#thn-journal-test-v2"},
                        "sk": {"S": "REGISTRY#V2"},
                    },
                    "ConsistentRead": True,
                }
            ],
        )

    def test_fails_closed_when_record_is_missing_duplicate_or_inactive(self):
        cases = {
            "missing": {},
            "duplicate": {"Items": [active_record(), active_record()]},
            "item-plus-items": {"Item": active_record(), "Items": [active_record()]},
            "inactive": {"Item": active_record(activationStatus="inactive")},
        }

        for label, response in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    consumer.ServiceBindingUnavailable,
                    "^service binding is unavailable$",
                ):
                    load(FakeDynamoClient(response))

    def test_fails_closed_on_every_ownership_or_fixed_binding_mismatch(self):
        mismatches = {
            "pk": "SERVICE_BINDING#test#other",
            "sk": "REGISTRY#V1",
            "recordType": "other-record",
            "schemaVersion": 1,
            "environment": "prod",
            "domain": "other.example.com",
            "serviceBindingId": "other-binding",
            "hubId": "other-hub",
            "tenantId": "other-tenant",
            "cookieNamespace": "other-cookie-namespace",
            "authProfileId": "other-profile",
            "adminOrigin": "https://other.thehairnarrative.com",
        }

        for field, value in mismatches.items():
            with self.subTest(field=field):
                with self.assertRaises(consumer.ServiceBindingUnavailable):
                    load(FakeDynamoClient({"Item": active_record(**{field: value})}))

        bad_owner = active_record()
        bad_owner["reservationOwner"]["tenantId"] = "other-tenant"
        with self.assertRaises(consumer.ServiceBindingUnavailable):
            load(FakeDynamoClient({"Item": bad_owner}))

    def test_fails_closed_on_stale_or_mismatched_immutable_coordinates(self):
        record_mismatches = {
            "descriptorVersionId": "test-v2",
            "descriptorSha256": "b" * 64,
            "authPolicyVersion": "journal-owner-v2",
            "registryRevision": 8,
        }
        for field, value in record_mismatches.items():
            with self.subTest(field=field):
                with self.assertRaises(consumer.ServiceBindingUnavailable):
                    load(FakeDynamoClient({"Item": active_record(**{field: value})}))

        with self.assertRaises(consumer.ServiceBindingUnavailable):
            load(
                FakeDynamoClient({"Item": active_record()}),
                expected_registry_revision=8,
            )

    def test_fails_closed_on_untrusted_resources_or_malformed_closed_record(self):
        bad_resource = active_record()
        bad_resource["resourceBindings"]["metadataTableArn"] = (
            "arn:aws:dynamodb:us-east-1:999999999999:table/"
            "zoolanding-content-hub-test-ThnContentHubV2Metadata"
        )
        malformed = active_record()
        malformed["unexpected"] = "private-sentinel-do-not-reflect"
        missing = active_record()
        del missing["writerEpoch"]

        for label, record in (
            ("resource", bad_resource),
            ("unknown-field", malformed),
            ("missing-field", missing),
            ("invalid-mode", active_record(writerMode="open")),
            ("invalid-epoch", active_record(writerEpoch=True)),
        ):
            with self.subTest(label=label):
                with self.assertRaises(consumer.ServiceBindingUnavailable) as caught:
                    load(FakeDynamoClient({"Item": record}))
                self.assertEqual(str(caught.exception), "service binding is unavailable")
                self.assertNotIn("private-sentinel", str(caught.exception))

    def test_validates_expected_inputs_before_reading_the_registry(self):
        cases = (
            {"expected_descriptor": {**EXPECTED_DESCRIPTOR, "unknown": "value"}},
            {"expected_descriptor": {**EXPECTED_DESCRIPTOR, "descriptorSha256": "not-a-hash"}},
            {"expected_registry_revision": True},
            {"trusted_resource_scope": {**TRUSTED_RESOURCE_SCOPE, "region": "invalid"}},
        )

        for arguments in cases:
            with self.subTest(arguments=arguments):
                client = FakeDynamoClient({"Item": active_record()})
                with self.assertRaises(consumer.ServiceBindingUnavailable):
                    load(client, **arguments)
                self.assertEqual(client.calls, [])

    def test_provider_and_attribute_value_errors_are_sanitized(self):
        cases = (
            FakeDynamoClient({}, error=RuntimeError("private-provider-sentinel")),
            FakeDynamoClient({"Item": {"pk": {"N": "not-an-integer"}}}),
        )

        for client in cases:
            with self.subTest(error=type(client.error).__name__ if client.error else "malformed"):
                with self.assertRaises(consumer.ServiceBindingUnavailable) as caught:
                    load(client)
                self.assertEqual(str(caught.exception), "service binding is unavailable")
                self.assertNotIn("private-provider-sentinel", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
