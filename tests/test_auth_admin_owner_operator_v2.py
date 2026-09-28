import inspect
import json
import unittest
from unittest.mock import patch

import auth_admin_owner_operator_v2 as mediator


OWNER_EMAIL = "owner@example.test"
TEMPORARY_PASSWORD = "Temporary-Only-8472!"
OPERATOR_ARN = (
    "arn:aws:sts::123456789012:assumed-role/"
    "zoolanding-thn-registry-test-operator/local"
)


def function_url_event(payload, *, method="POST", caller_arn=OPERATOR_ARN):
    return {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": "/",
        "rawQueryString": "",
        "headers": {"content-type": "application/json"},
        "requestContext": {
            "authorizer": {"iam": {"userArn": caller_arn}},
            "domainName": "example.lambda-url.us-east-1.on.aws",
            "http": {"method": method, "path": "/"},
        },
        "body": json.dumps(payload, separators=(",", ":")),
        "isBase64Encoded": False,
    }


def response_body(response):
    return json.loads(response["body"])


class RecordingSession:
    def __init__(self):
        self.region_name = "us-east-1"
        self.dynamodb = object()
        self.client_names = []

    def client(self, service_name):
        self.client_names.append(service_name)
        if service_name == "dynamodb":
            return self.dynamodb
        raise AssertionError(f"unexpected service client: {service_name}")


class ThnOwnerOperatorMediatorTests(unittest.TestCase):
    def test_rejects_unknown_or_malformed_payload_before_creating_an_aws_session(self):
        invalid = (
            None,
            {},
            {"contractVersion": 1, "operation": "disable", "username": OWNER_EMAIL},
            function_url_event(
                {"contractVersion": 1, "operation": "unknown", "username": OWNER_EMAIL}
            ),
            function_url_event(
                {
                    "contractVersion": 1,
                    "operation": "disable",
                    "username": OWNER_EMAIL,
                    "temporaryPassword": TEMPORARY_PASSWORD,
                }
            ),
            function_url_event(
                {"contractVersion": 1, "operation": "reset", "username": OWNER_EMAIL}
            ),
            function_url_event(
                {
                    "contractVersion": 1,
                    "operation": "disable",
                    "username": OWNER_EMAIL,
                    "extra": True,
                }
            ),
            function_url_event(
                {"contractVersion": 1, "operation": "disable", "username": OWNER_EMAIL},
                method="GET",
            ),
        )

        with patch.object(mediator, "_new_session") as session_factory:
            for event in invalid:
                with self.subTest(event=event):
                    response = mediator.lambda_handler(event, None)
                    self.assertEqual(response["statusCode"], 400)
                    self.assertEqual(
                        response_body(response),
                        {"ok": False, "error": "owner operation failed"},
                    )

        session_factory.assert_not_called()

    def test_rejects_an_unapproved_function_url_principal_before_creating_a_session(self):
        event = function_url_event(
            {"contractVersion": 1, "operation": "disable", "username": OWNER_EMAIL},
            caller_arn="arn:aws:iam::123456789012:role/other-role",
        )
        with (
            patch.object(
                mediator.owner,
                "require_named_operator",
                side_effect=mediator.owner.OperatorAuthorizationError("denied"),
            ) as authorize,
            patch.object(mediator, "_new_session") as session_factory,
        ):
            response = mediator.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(response_body(response), {"ok": False, "error": "owner operation failed"})
        authorize.assert_called_once_with("arn:aws:iam::123456789012:role/other-role")
        session_factory.assert_not_called()

    def test_invokes_only_the_reviewed_owner_core_with_create_only_audit(self):
        session = RecordingSession()
        expected = {
            "ok": True,
            "operation": "reset",
            "accountPurpose": "client-owner",
            "sessionVersion": 9,
            "enabled": False,
        }
        event = function_url_event(
            {
                "contractVersion": 1,
                "operation": "reset",
                "username": OWNER_EMAIL,
                "temporaryPassword": TEMPORARY_PASSWORD,
            }
        )

        with (
            patch.object(mediator.owner, "require_named_operator"),
            patch.object(mediator, "_new_session", return_value=session),
            patch.object(mediator, "DynamoCurrentUserStateClient") as state_type,
            patch.object(mediator, "DynamoAuditEventSink") as audit_type,
            patch.object(mediator, "execute_operation", return_value=expected) as execute,
        ):
            result = mediator.lambda_handler(event, None)

        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(response_body(result), expected)
        self.assertEqual(result["headers"]["cache-control"], "no-store, max-age=0")
        self.assertEqual(result["headers"]["pragma"], "no-cache")
        self.assertEqual(result["headers"]["referrer-policy"], "no-referrer")
        self.assertNotIn("access-control-allow-origin", result["headers"])
        self.assertEqual(session.client_names, ["dynamodb"])
        state_type.assert_called_once_with(session.dynamodb)
        audit_type.assert_called_once_with(session.dynamodb)
        execute.assert_called_once_with(
            session,
            state_client=state_type.return_value,
            operation="reset",
            username=OWNER_EMAIL,
            temporary_password=TEMPORARY_PASSWORD,
            event_sink=audit_type.return_value,
            authorized_by_mediator=True,
        )

    def test_provider_or_private_input_never_appears_in_the_public_failure(self):
        sentinel = f"private {OWNER_EMAIL} {TEMPORARY_PASSWORD} provider detail"
        session = RecordingSession()
        event = function_url_event(
            {
                "contractVersion": 1,
                "operation": "create",
                "username": OWNER_EMAIL,
                "temporaryPassword": TEMPORARY_PASSWORD,
            }
        )
        with (
            patch.object(mediator.owner, "require_named_operator"),
            patch.object(mediator, "_new_session", return_value=session),
            patch.object(mediator, "DynamoCurrentUserStateClient"),
            patch.object(mediator, "DynamoAuditEventSink"),
            patch.object(mediator, "execute_operation", side_effect=RuntimeError(sentinel)),
        ):
            with self.assertRaises(mediator.OwnerMediatorFailure) as caught:
                mediator.lambda_handler(event, None)

        rendered = repr(caught.exception)
        self.assertEqual(str(caught.exception), "owner operation failed")
        self.assertNotIn(OWNER_EMAIL, rendered)
        self.assertNotIn(TEMPORARY_PASSWORD, rendered)
        self.assertNotIn("provider detail", rendered)

    def test_handler_has_no_logging_or_browser_cors_surface(self):
        source = inspect.getsource(mediator)

        self.assertNotIn("print(", source)
        self.assertNotIn("logging", source)
        self.assertNotIn("logger", source.lower())
        self.assertNotIn("access-control-allow-origin", source.lower())


if __name__ == "__main__":
    unittest.main()
