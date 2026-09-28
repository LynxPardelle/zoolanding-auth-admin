import copy
import json
import unittest
from unittest.mock import patch

import auth_admin_session_v2 as session_v2
import lambda_function as auth_admin
import service_binding_registry_consumer_v2 as registry_consumer


ADMIN_HOST = "admin-test.thehairnarrative.com"
ADMIN_ORIGIN = f"https://{ADMIN_HOST}"
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
        "pk": registry_consumer.APPROVED_PARTITION_KEY,
        "sk": registry_consumer.APPROVED_SORT_KEY,
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
        "adminOrigin": ADMIN_ORIGIN,
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


class FakeRegistryClient:
    def __init__(self, response, timeline=None):
        self.response = copy.deepcopy(response)
        if "Item" in self.response and isinstance(self.response["Item"], dict):
            self.response["Item"] = registry_consumer.marshal_item(
                self.response["Item"]
            )
        self.timeline = timeline
        self.calls = []

    def get_item(self, **kwargs):
        request = copy.deepcopy(kwargs)
        self.calls.append(request)
        if self.timeline is not None:
            self.timeline.append("binding-read")
        return copy.deepcopy(self.response)


def v2_event(method, path, body=None, *, host=ADMIN_HOST, origin=ADMIN_ORIGIN):
    return {
        "version": "2.0",
        "routeKey": f"{method} {path}",
        "rawPath": path,
        "headers": {
            "host": host,
            "origin": origin,
            "x-forwarded-host": ADMIN_HOST,
            "x-zlp-viewer-ip": "203.0.113.10",
        },
        "requestContext": {
            "authorizer": {
                "lambda": {
                    "originVerified": True,
                    "viewerIp": "203.0.113.10",
                }
            },
            "http": {
                "method": method,
                "path": path,
                "sourceIp": "203.0.113.10",
            },
            "requestId": "registry-fence-v2",
        },
        "body": json.dumps(body) if body is not None else None,
    }


def response_body(response):
    return json.loads(response.get("body") or "{}")


class AuthAdminV2RegistryFenceTests(unittest.TestCase):
    def binding_patches(self, client):
        return (
            patch.object(
                session_v2,
                "_service_binding_registry_client",
                return_value=client,
                create=True,
            ),
            patch.object(
                session_v2,
                "_service_binding_expected_descriptor",
                return_value=copy.deepcopy(EXPECTED_DESCRIPTOR),
                create=True,
            ),
            patch.object(
                session_v2,
                "_service_binding_trusted_resource_scope",
                return_value=copy.deepcopy(TRUSTED_RESOURCE_SCOPE),
                create=True,
            ),
        )

    def test_active_binding_is_read_by_exact_consistent_key_before_route_dispatch(self):
        timeline = []
        client = FakeRegistryClient({"Item": active_record()}, timeline=timeline)

        def signin_response(_event):
            timeline.append("route-dispatch")
            return {
                "statusCode": 200,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"ok": True}),
            }

        client_patch, descriptor_patch, scope_patch = self.binding_patches(client)
        with (
            client_patch,
            descriptor_patch,
            scope_patch,
            patch.object(
                session_v2,
                "_signin_response",
                side_effect=signin_response,
            ),
        ):
            response = session_v2.lambda_handler(
                v2_event(
                    "POST",
                    "/auth-v2/session/signin",
                    {"email": "owner@example.test", "password": "ValidPass123!"},
                ),
                object(),
            )

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(timeline, ["binding-read", "route-dispatch"])
        self.assertEqual(
            client.calls,
            [
                {
                    "TableName": registry_consumer.APPROVED_TABLE_NAME,
                    "Key": registry_consumer.marshal_item(
                        {
                            "pk": registry_consumer.APPROVED_PARTITION_KEY,
                            "sk": registry_consumer.APPROVED_SORT_KEY,
                        }
                    ),
                    "ConsistentRead": True,
                }
            ],
        )

    def test_missing_or_mismatched_binding_returns_503_before_store_or_cognito(self):
        mismatch = active_record(domain="other.example.com")
        cases = {
            "missing": {},
            "mismatch": {"Item": mismatch},
        }

        for label, registry_response in cases.items():
            with self.subTest(label=label):
                client = FakeRegistryClient(registry_response)
                touched = []

                def forbidden_store():
                    touched.append("store")
                    return object()

                def forbidden_cognito():
                    touched.append("cognito")
                    return object()

                client_patch, descriptor_patch, scope_patch = self.binding_patches(client)
                with (
                    client_patch,
                    descriptor_patch,
                    scope_patch,
                    patch.object(
                        session_v2,
                        "_cognito_configuration",
                        return_value=(
                            "us-east-1",
                            "us-east-1_testpool",
                            "test-client-id",
                        ),
                    ),
                    patch.object(
                        session_v2, "_session_store", side_effect=forbidden_store
                    ),
                    patch.object(
                        session_v2, "_cognito_client", side_effect=forbidden_cognito
                    ),
                    patch.object(session_v2, "_safe_log"),
                ):
                    response = session_v2.lambda_handler(
                        v2_event(
                            "POST",
                            "/auth-v2/session/signin",
                            {
                                "email": "owner@example.test",
                                "password": "ValidPass123!",
                            },
                        ),
                        object(),
                    )

                self.assertEqual(response["statusCode"], 503)
                self.assertEqual(
                    response_body(response),
                    {
                        "ok": False,
                        "error": "Authentication temporarily unavailable",
                        "errorCode": "auth_unavailable",
                    },
                )
                self.assertEqual(touched, [])
                self.assertEqual(len(client.calls), 1)
                self.assertTrue(client.calls[0]["ConsistentRead"])

    def test_origin_is_rejected_before_the_registry_is_read(self):
        client = FakeRegistryClient({"Item": active_record()})
        client_patch, descriptor_patch, scope_patch = self.binding_patches(client)

        with client_patch, descriptor_patch, scope_patch:
            response = session_v2.lambda_handler(
                v2_event(
                    "POST",
                    "/auth-v2/session/signin",
                    host="test.zoolandingpage.com.mx",
                    origin="https://test.zoolandingpage.com.mx",
                ),
                object(),
            )

        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(client.calls, [])

    def test_legacy_v1_handler_does_not_read_the_v2_registry(self):
        event = {
            "version": "2.0",
            "routeKey": "OPTIONS /auth/session/signin",
            "rawPath": "/auth/session/signin",
            "headers": {},
            "requestContext": {
                "http": {
                    "method": "OPTIONS",
                    "path": "/auth/session/signin",
                    "sourceIp": "203.0.113.10",
                }
            },
        }

        with patch.object(
            registry_consumer,
            "load_active_service_binding",
            side_effect=AssertionError("v1 must not read the v2 registry"),
        ) as registry_read:
            response = auth_admin.lambda_handler(event, object())

        self.assertEqual(response["statusCode"], 200)
        registry_read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
