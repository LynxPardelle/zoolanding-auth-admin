import hashlib
import importlib
import os
import unittest
from unittest.mock import patch


HEADER_NAME = "x-zlp-origin-verify"
CURRENT_SECRET = "a" * 43
PREVIOUS_SECRET = "b" * 43
ADMIN_HOST = "admin-test.thehairnarrative.com"
ADMIN_ORIGIN = f"https://{ADMIN_HOST}"


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event(secret=CURRENT_SECRET, *, method="POST", path="/auth-v2/session/signin"):
    return {
        "version": "2.0",
        "type": "REQUEST",
        "routeArn": (
            "arn:aws:execute-api:us-east-1:123456789012:api-id/"
            f"test/{method}{path}"
        ),
        "identitySource": [secret],
        "routeKey": f"{method} {path}",
        "rawPath": path,
        "headers": {
            HEADER_NAME: secret,
            "x-zlp-viewer-ip": "2001:0db8:0:0:0:0:0:1",
            "x-forwarded-host": ADMIN_HOST,
            "origin": ADMIN_ORIGIN,
        },
        "requestContext": {
            "accountId": "123456789012",
            "apiId": "api-id",
            "routeKey": f"{method} {path}",
            "stage": "test",
            "http": {"method": method, "path": path},
        },
    }


class AuthAdminOriginAuthorizerV2Tests(unittest.TestCase):
    def setUp(self):
        try:
            self.authorizer = importlib.import_module("auth_admin_origin_authorizer_v2")
        except ModuleNotFoundError:
            self.fail("the isolated Auth Admin v2 origin authorizer is missing")
        self.environment = {
            "THN_AUTH_V2_ORIGIN_HEADER_SHA256_CURRENT": _digest(CURRENT_SECRET),
            "THN_AUTH_V2_ORIGIN_HEADER_SHA256_PREVIOUS": _digest(PREVIOUS_SECRET),
        }

    def invoke(self, event, **environment):
        values = {**self.environment, **environment}
        with patch.dict(os.environ, values, clear=True):
            return self.authorizer.lambda_handler(event, None)

    def test_exact_current_and_previous_origin_proofs_are_accepted(self):
        for secret in (CURRENT_SECRET, PREVIOUS_SECRET):
            with self.subTest(secret=secret[:8]):
                self.assertEqual(
                    self.invoke(_event(secret)),
                    {
                        "isAuthorized": True,
                        "context": {
                            "originVerified": True,
                            "viewerIp": "2001:db8::1",
                        },
                    },
                )

    def test_missing_wrong_or_duplicated_origin_proof_is_denied_generically(self):
        candidates = []

        missing = _event()
        missing["headers"] = {}
        missing["identitySource"] = []
        candidates.append(missing)

        wrong = _event("c" * 43)
        candidates.append(wrong)

        duplicated = _event()
        duplicated["headers"]["X-ZLP-Origin-Verify"] = CURRENT_SECRET
        candidates.append(duplicated)

        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.assertEqual(
                    self.invoke(candidate),
                    {"isAuthorized": False, "context": {}},
                )

    def test_only_the_six_exact_test_routes_can_be_authorized(self):
        accepted = {
            ("POST", "/auth-v2/session/signin"),
            ("POST", "/auth-v2/session/challenge/respond"),
            ("POST", "/auth-v2/session/mfa/setup"),
            ("POST", "/auth-v2/session/mfa/verify"),
            ("GET", "/auth-v2/session/me"),
            ("POST", "/auth-v2/session/logout"),
        }
        for method, path in accepted:
            with self.subTest(method=method, path=path):
                self.assertTrue(self.invoke(_event(method=method, path=path))["isAuthorized"])

        for method, path in (
            ("GET", "/auth-v2/session/signin"),
            ("POST", "/auth-v2/runtime-config"),
            ("POST", "/auth-v2/session/signin/"),
            ("POST", "/auth/session/signin"),
        ):
            with self.subTest(method=method, path=path):
                self.assertFalse(self.invoke(_event(method=method, path=path))["isAuthorized"])

        wrong_stage = _event()
        wrong_stage["requestContext"]["stage"] = "prod"
        wrong_stage["routeArn"] = wrong_stage["routeArn"].replace("/test/", "/prod/")
        self.assertFalse(self.invoke(wrong_stage)["isAuthorized"])

    def test_viewer_ip_host_origin_and_api_envelope_are_fenced(self):
        invalid_events = []
        for header, value in (
            ("x-zlp-viewer-ip", "not-an-ip"),
            ("x-zlp-viewer-ip", "203.0.113.1, 203.0.113.2"),
            ("x-forwarded-host", "test.zoolandingpage.com.mx"),
            ("origin", "https://test.zoolandingpage.com.mx"),
        ):
            event = _event()
            event["headers"][header] = value
            invalid_events.append(event)

        wrong_api = _event()
        wrong_api["requestContext"]["apiId"] = "other-api"
        invalid_events.append(wrong_api)

        wrong_account = _event()
        wrong_account["requestContext"]["accountId"] = "000000000000"
        invalid_events.append(wrong_account)

        wrong_context_route = _event()
        wrong_context_route["requestContext"]["routeKey"] = "GET /auth-v2/session/me"
        invalid_events.append(wrong_context_route)

        for event in invalid_events:
            with self.subTest(headers=event["headers"]):
                self.assertEqual(
                    self.invoke(event),
                    {"isAuthorized": False, "context": {}},
                )

        get_without_origin = _event(method="GET", path="/auth-v2/session/me")
        get_without_origin["headers"].pop("origin")
        self.assertTrue(self.invoke(get_without_origin)["isAuthorized"])

    def test_route_metadata_mismatch_and_invalid_digest_configuration_fail_closed(self):
        mismatch = _event()
        mismatch["routeKey"] = "GET /auth-v2/session/me"
        self.assertFalse(self.invoke(mismatch)["isAuthorized"])

        invalid_current = {
            "THN_AUTH_V2_ORIGIN_HEADER_SHA256_CURRENT": "0" * 64,
            "THN_AUTH_V2_ORIGIN_HEADER_SHA256_PREVIOUS": "0" * 64,
        }
        self.assertEqual(
            self.invoke(_event(), **invalid_current),
            {"isAuthorized": False, "context": {}},
        )

        duplicated_rotation = {
            "THN_AUTH_V2_ORIGIN_HEADER_SHA256_CURRENT": _digest(CURRENT_SECRET),
            "THN_AUTH_V2_ORIGIN_HEADER_SHA256_PREVIOUS": _digest(CURRENT_SECRET),
        }
        self.assertEqual(
            self.invoke(_event(), **duplicated_rotation),
            {"isAuthorized": False, "context": {}},
        )


if __name__ == "__main__":
    unittest.main()
