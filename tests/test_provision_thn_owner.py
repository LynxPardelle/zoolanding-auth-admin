import inspect
import io
import hashlib
import json
import pathlib
import subprocess
import sys
import types
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from tools import provision_thn_owner as owner


ACCOUNT_ID = "123456789012"
OWNER_EMAIL = "owner@example.test"
TEMPORARY_PASSWORD = "Temp-Only-Password-8472!"
USER_POOL_ID = "us-east-1_ThnOwnerPool"
CLIENT_ID = "7mthnownerclientexample"
COGNITO_USERNAME = "cognito-owner-handle"
SUBJECT = "owner-subject-123"
FUNCTION_URL = "https://example.lambda-url.us-east-1.on.aws/"


def fake_botocore_modules(response):
    records = {}

    class FakeAWSRequest:
        def __init__(self, *, method, url, data, headers):
            self.method = method
            self.url = url
            self.data = data
            self.headers = dict(headers)

        def prepare(self):
            return types.SimpleNamespace(
                method=self.method,
                url=self.url,
                body=self.data,
                headers=dict(self.headers),
            )

    class FakeSigV4Auth:
        def __init__(self, credentials, service, region):
            records["signer"] = (credentials, service, region)

        def add_auth(self, request):
            request.headers["Authorization"] = "AWS4-HMAC-SHA256 synthetic"

    class FakeURLLib3Session:
        def __init__(self, *, timeout):
            records["timeout"] = timeout

        def send(self, prepared):
            records["prepared"] = prepared
            return response

    root = types.ModuleType("botocore")
    auth = types.ModuleType("botocore.auth")
    awsrequest = types.ModuleType("botocore.awsrequest")
    httpsession = types.ModuleType("botocore.httpsession")
    auth.SigV4Auth = FakeSigV4Auth
    awsrequest.AWSRequest = FakeAWSRequest
    httpsession.URLLib3Session = FakeURLLib3Session
    return {
        "botocore": root,
        "botocore.auth": auth,
        "botocore.awsrequest": awsrequest,
        "botocore.httpsession": httpsession,
    }, records

# Production keeps this digest as a reviewed code-owned activation value. Tests
# replace the inert sentinel with the digest of their synthetic account only.
owner.APPROVED_AWS_ACCOUNT_ID_SHA256 = hashlib.sha256(
    ACCOUNT_ID.encode("ascii")
).hexdigest()


class UsernameExistsError(RuntimeError):
    def __init__(self):
        super().__init__("provider username exists")
        self.response = {"Error": {"Code": "UsernameExistsException"}}


class UserNotFoundError(RuntimeError):
    def __init__(self):
        super().__init__("provider user does not exist")
        self.response = {"Error": {"Code": "UserNotFoundException"}}


class RecordingCloudFormationClient:
    def __init__(self, *, pool_id=USER_POOL_ID, client_id=CLIENT_ID):
        self.physical_ids = {
            "ThnAuthAdminV2UserPool": pool_id,
            "ThnAuthAdminV2UserPoolClient": client_id,
            "ThnAuthAdminV2OwnerGroup": "journal-owner",
        }
        self.calls = []

    def describe_stack_resource(self, **kwargs):
        self.calls.append(kwargs)
        logical_id = kwargs["LogicalResourceId"]
        return {
            "StackResourceDetail": {
                "LogicalResourceId": logical_id,
                "PhysicalResourceId": self.physical_ids[logical_id],
                "ResourceStatus": "CREATE_COMPLETE",
            }
        }


def secure_pool(*, pool_id=USER_POOL_ID, name=None, **overrides):
    value = {
        "Id": pool_id,
        "Name": name or "zoolanding-auth-admin-test-ThnAuthAdminV2",
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
        "MfaConfiguration": "ON",
        "EnabledMfas": ["SOFTWARE_TOKEN_MFA"],
        "LambdaConfig": {},
        "AccountRecoverySetting": {
            "RecoveryMechanisms": [{"Priority": 1, "Name": "admin_only"}],
        },
    }
    value.update(overrides)
    return value


def dedicated_client(*, client_id=CLIENT_ID, name=None, **overrides):
    value = {
        "UserPoolId": USER_POOL_ID,
        "ClientId": client_id,
        "ClientName": name or "zoolanding-auth-admin-test-ThnAuthAdminV2Client",
        "ExplicitAuthFlows": ["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        "PreventUserExistenceErrors": "ENABLED",
        "EnableTokenRevocation": True,
        "AuthSessionValidity": 5,
    }
    value.update(overrides)
    return value


class RecordingStsClient:
    def __init__(self, arn=None, account=ACCOUNT_ID):
        self.arn = arn or (
            "arn:aws:sts::123456789012:assumed-role/"
            "zoolanding-thn-registry-test-operator/github-actions"
        )
        self.account = account

    def get_caller_identity(self):
        return {"Arn": self.arn, "Account": self.account}


class RecordingLambdaClient:
    def __init__(self, *, function_url=FUNCTION_URL, auth_type="AWS_IAM"):
        self.function_url = function_url
        self.auth_type = auth_type
        self.calls = []

    def get_function_url_config(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "FunctionUrl": self.function_url,
            "FunctionArn": (
                "arn:aws:lambda:us-east-1:123456789012:function:"
                "zoolanding-auth-admin-test-ThnOwnerOperatorV2:test"
            ),
            "AuthType": self.auth_type,
        }

    def invoke(self, **kwargs):
        raise AssertionError(f"direct Lambda invoke is forbidden: {sorted(kwargs)}")


class RecordingCognitoClient:
    def __init__(
        self,
        *,
        pools=None,
        clients=None,
        groups=None,
        user_groups=None,
        described_pool=None,
        described_client=None,
        provider_error=None,
        users_in_group=None,
        provider_username=COGNITO_USERNAME,
        subject=SUBJECT,
        email=OWNER_EMAIL,
        username_exists_on_create=False,
        user_exists_before_create=True,
        create_commits_then_raises=False,
        preserve_users_in_group_on_create=False,
    ):
        self.provider_username = provider_username
        self.subject = subject
        self.email = email
        self.username_exists_on_create = username_exists_on_create
        self.user_exists = user_exists_before_create or username_exists_on_create
        self.create_commits_then_raises = create_commits_then_raises
        self.preserve_users_in_group_on_create = preserve_users_in_group_on_create
        self.pools = list(pools if pools is not None else [secure_pool()])
        self.clients = list(clients if clients is not None else [dedicated_client()])
        self.groups = list(groups if groups is not None else [{"GroupName": "journal-owner"}])
        self.user_groups = list(
            user_groups if user_groups is not None else [{"GroupName": "journal-owner"}]
        )
        self.described_pool = described_pool or secure_pool()
        self.described_client = described_client or dedicated_client()
        self.provider_error = provider_error
        self.users_in_group = list(
            users_in_group
            if users_in_group is not None
            else [{"Username": provider_username, "Attributes": [{"Name": "sub", "Value": subject}]}]
        )
        self.calls = []

    def _record(self, method, kwargs):
        self.calls.append((method, kwargs))
        if self.provider_error == method:
            raise RuntimeError(
                f"provider sentinel {OWNER_EMAIL} {TEMPORARY_PASSWORD} {USER_POOL_ID}"
            )

    def list_user_pools(self, **kwargs):
        self._record("list_user_pools", kwargs)
        return {"UserPools": self.pools}

    def get_group(self, **kwargs):
        self._record("get_group", kwargs)
        matches = [group for group in self.groups if group.get("GroupName") == kwargs["GroupName"]]
        return {"Group": matches[0]} if len(matches) == 1 else {}

    def describe_user_pool(self, **kwargs):
        self._record("describe_user_pool", kwargs)
        return {"UserPool": self.described_pool}

    def list_user_pool_clients(self, **kwargs):
        self._record("list_user_pool_clients", kwargs)
        return {"UserPoolClients": self.clients}

    def describe_user_pool_client(self, **kwargs):
        self._record("describe_user_pool_client", kwargs)
        return {"UserPoolClient": self.described_client}

    def list_groups(self, **kwargs):
        self._record("list_groups", kwargs)
        return {"Groups": self.groups}

    def list_users_in_group(self, **kwargs):
        self._record("list_users_in_group", kwargs)
        return {"Users": self.users_in_group}

    def admin_create_user(self, **kwargs):
        self._record("admin_create_user", kwargs)
        if self.username_exists_on_create:
            raise UsernameExistsError()
        self.user_exists = True
        if not self.preserve_users_in_group_on_create:
            self.users_in_group = []
        if self.create_commits_then_raises:
            raise RuntimeError("provider response was lost")
        return {
            "User": {
                "Username": self.provider_username,
                "UserStatus": "FORCE_CHANGE_PASSWORD",
                "Attributes": [
                    {"Name": "sub", "Value": self.subject},
                    {"Name": "email", "Value": self.email},
                    {"Name": "email_verified", "Value": "true"},
                ],
            }
        }

    def admin_get_user(self, **kwargs):
        self._record("admin_get_user", kwargs)
        if not self.user_exists:
            raise UserNotFoundError()
        return {
            "Username": self.provider_username,
            "UserStatus": "FORCE_CHANGE_PASSWORD",
            "Enabled": True,
            "UserAttributes": [
                {"Name": "sub", "Value": self.subject},
                {"Name": "email", "Value": self.email},
                {"Name": "email_verified", "Value": "true"},
            ],
        }

    def admin_add_user_to_group(self, **kwargs):
        self._record("admin_add_user_to_group", kwargs)
        self.user_groups = [{"GroupName": "journal-owner"}]
        self.users_in_group = [
            {
                "Username": self.provider_username,
                "Attributes": [{"Name": "sub", "Value": self.subject}],
            }
        ]
        return {}

    def admin_remove_user_from_group(self, **kwargs):
        self._record("admin_remove_user_from_group", kwargs)
        self.user_groups = []
        self.users_in_group = []
        return {}

    def admin_list_groups_for_user(self, **kwargs):
        self._record("admin_list_groups_for_user", kwargs)
        return {"Groups": self.user_groups}

    def admin_enable_user(self, **kwargs):
        self._record("admin_enable_user", kwargs)
        return {}

    def admin_disable_user(self, **kwargs):
        self._record("admin_disable_user", kwargs)
        return {}

    def admin_user_global_sign_out(self, **kwargs):
        self._record("admin_user_global_sign_out", kwargs)
        return {}

    def admin_set_user_password(self, **kwargs):
        self._record("admin_set_user_password", kwargs)
        return {}

    def admin_set_user_mfa_preference(self, **kwargs):
        self._record("admin_set_user_mfa_preference", kwargs)
        return {}

    def admin_delete_software_token(self, **kwargs):
        self._record("admin_delete_software_token", kwargs)
        return {}


class RecordingSession:
    def __init__(
        self,
        *,
        sts=None,
        cognito=None,
        cloudformation=None,
        lambda_client=None,
        region_name="us-east-1",
    ):
        self.region_name = region_name
        self.sts = sts or RecordingStsClient()
        self.cognito = cognito or RecordingCognitoClient()
        self.cloudformation = cloudformation or RecordingCloudFormationClient()
        self.lambda_client = lambda_client or RecordingLambdaClient()
        self.client_names = []
        self.credential_reads = 0

    def client(self, service_name):
        self.client_names.append(service_name)
        if service_name == "sts":
            return self.sts
        if service_name == "cognito-idp":
            return self.cognito
        if service_name == "cloudformation":
            return self.cloudformation
        if service_name == "lambda":
            return self.lambda_client
        raise AssertionError(f"unexpected service client: {service_name}")

    def get_credentials(self):
        self.credential_reads += 1

        return types.SimpleNamespace(
            get_frozen_credentials=lambda: "synthetic-frozen-credentials"
        )


class RecordingCurrentUserStateClient:
    def __init__(self, state=None, *, owner_subject=None):
        self.state = dict(
            state
            or {
                "subject": SUBJECT,
                "accountPurpose": "client-owner",
                "sessionVersion": 7,
                "enabled": True,
            }
        )
        self.owner_subject = owner_subject
        self.calls = []

    def provision(self, *, subject, account_purpose):
        self.calls.append(("provision", {"subject": subject, "accountPurpose": account_purpose}))
        if account_purpose != "client-owner":
            raise AssertionError("account purpose must be code-owned")
        if self.owner_subject is not None and self.owner_subject != subject:
            raise RuntimeError("singleton owner already reserved")
        if self.owner_subject == subject:
            return dict(self.state)
        self.owner_subject = subject
        self.state = {
            "subject": subject,
            "accountPurpose": account_purpose,
            "sessionVersion": 1,
            "enabled": False,
        }
        return dict(self.state)

    def enable(self, *, subject, account_purpose):
        self.calls.append(("enable", {"subject": subject, "accountPurpose": account_purpose}))
        self._require_owner(subject, account_purpose)
        if self.state["enabled"] is False:
            self.state["sessionVersion"] += 1
            self.state["enabled"] = True
        return dict(self.state)

    def disable(self, *, subject, account_purpose):
        self.calls.append(("disable", {"subject": subject, "accountPurpose": account_purpose}))
        self._require_owner(subject, account_purpose)
        if self.state["enabled"]:
            self.state["sessionVersion"] += 1
            self.state["enabled"] = False
        return dict(self.state)

    def reset(self, *, subject, account_purpose):
        self.calls.append(("reset", {"subject": subject, "accountPurpose": account_purpose}))
        self._require_owner(subject, account_purpose)
        if self.state["enabled"]:
            self.state["sessionVersion"] += 1
            self.state["enabled"] = False
        return dict(self.state)

    def repair_session_version(self, *, subject, account_purpose):
        self.calls.append(
            ("repair_session_version", {"subject": subject, "accountPurpose": account_purpose})
        )
        self._require_owner(subject, account_purpose)
        self.state["sessionVersion"] += 1
        return dict(self.state)

    def _require_owner(self, subject, account_purpose):
        if (
            subject != self.state["subject"]
            or account_purpose != "client-owner"
            or self.state["accountPurpose"] != "client-owner"
        ):
            raise AssertionError("state operation crossed the immutable owner boundary")


class FailingProvisionStateClient(RecordingCurrentUserStateClient):
    def provision(self, *, subject, account_purpose):
        self.calls.append(("provision", {"subject": subject, "accountPurpose": account_purpose}))
        raise RuntimeError(f"state sentinel {OWNER_EMAIL} {TEMPORARY_PASSWORD}")


class FailingEventSink:
    def __init__(self, *, fail_on_call):
        self.fail_on_call = fail_on_call
        self.events = []

    def __call__(self, event):
        self.events.append(dict(event))
        if len(self.events) == self.fail_on_call:
            raise owner.OwnerOperationError("owner audit append failed")


def calls_for(client, method):
    return [kwargs for called, kwargs in client.calls if called == method]


class ThnOwnerOperatorIdentityTests(unittest.TestCase):
    def test_cli_help_runs_from_the_repository_root_without_importing_boto3(self):
        repository_root = pathlib.Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            [sys.executable, "tools/provision_thn_owner.py", "--help"],
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Operate the dedicated THN TEST owner account", completed.stdout)

    def test_no_workflow_can_invoke_owner_provisioning_automatically(self):
        repository_root = pathlib.Path(__file__).resolve().parents[1]
        for workflow in sorted((repository_root / ".github" / "workflows").glob("*.y*ml")):
            with self.subTest(workflow=workflow.name):
                source = workflow.read_text(encoding="utf-8")
                self.assertNotIn("provision_thn_owner", source)
                self.assertNotIn("ThnAuthAdminV2OwnerOperatorPolicy", source)

    def test_only_named_test_operator_role_or_its_session_is_accepted(self):
        direct = "arn:aws:iam::123456789012:role/zoolanding-thn-registry-test-operator"
        assumed = (
            "arn:aws:sts::123456789012:assumed-role/"
            "zoolanding-thn-registry-test-operator/operator-session"
        )

        self.assertEqual(owner.require_named_operator(direct), direct)
        self.assertEqual(owner.require_named_operator(assumed), direct)

        for caller in (
            "arn:aws:iam::123456789012:role/zoolanding-auth-admin-test-role",
            "arn:aws:iam::123456789012:user/administrator",
            "arn:aws:sts::999999999999:assumed-role/"
            "zoolanding-thn-registry-test-operator/session",
        ):
            with self.subTest(caller=caller):
                with self.assertRaises(owner.OperatorAuthorizationError):
                    owner.require_named_operator(caller)

    def test_unknown_operator_is_denied_before_any_cognito_or_state_access(self):
        session = RecordingSession(
            sts=RecordingStsClient(
                arn="arn:aws:iam::123456789012:role/unapproved-operator"
            )
        )
        state = RecordingCurrentUserStateClient()

        with self.assertRaises(owner.OperatorAuthorizationError):
            owner.execute_operation(
                session,
                state_client=state,
                operation="disable",
                username=OWNER_EMAIL,
            )

        self.assertEqual(session.client_names, ["sts"])
        self.assertEqual(session.cognito.calls, [])
        self.assertEqual(state.calls, [])

    def test_homonymous_operator_in_another_account_is_denied_by_code_owned_anchor(self):
        session = RecordingSession(
            sts=RecordingStsClient(
                arn=(
                    "arn:aws:sts::999999999999:assumed-role/"
                    "zoolanding-thn-registry-test-operator/session"
                ),
                account="999999999999",
            )
        )
        state = RecordingCurrentUserStateClient()

        with self.assertRaises(owner.OperatorAuthorizationError):
            owner.execute_operation(
                session,
                state_client=state,
                operation="repair-session-version",
                username=OWNER_EMAIL,
            )

        self.assertEqual(session.client_names, ["sts"])
        self.assertEqual(state.calls, [])

    def test_same_operator_in_another_region_is_denied_before_sts_or_data_access(self):
        session = RecordingSession(region_name="us-west-2")
        state = RecordingCurrentUserStateClient()

        with self.assertRaises(owner.OperatorAuthorizationError):
            owner.execute_operation(
                session,
                state_client=state,
                operation="repair-session-version",
                username=OWNER_EMAIL,
                event_sink=lambda _event: None,
            )

        self.assertEqual(session.client_names, [])
        self.assertEqual(state.calls, [])

    def test_cli_has_closed_actions_and_no_resource_or_purpose_selectors(self):
        parser = owner.build_parser()
        cases = (
            ["create"],
            ["enable"],
            ["disable"],
            ["reset"],
            ["repair-session-version"],
        )
        for argv in cases:
            with self.subTest(argv=argv):
                parsed = parser.parse_args(argv)
                self.assertNotIn("account_purpose", vars(parsed))
                self.assertNotIn("user_pool_id", vars(parsed))
                self.assertNotIn("client_id", vars(parsed))
                self.assertNotIn("group_name", vars(parsed))

        for forbidden in (
            ["create", "--username", OWNER_EMAIL],
            ["create", "--temporary-password", TEMPORARY_PASSWORD],
            ["disable", "--user-pool-id", "zoosite-pool"],
            ["reset", "--lifecycle-function", "legacy"],
            ["repair-session-version", "--region", "us-west-2"],
        ):
            with self.subTest(forbidden=forbidden), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(forbidden)

    def test_cli_uses_only_the_exact_signed_synchronous_function_url(self):
        lambda_client = RecordingLambdaClient()
        session = RecordingSession(lambda_client=lambda_client)
        response_payload = {
            "ok": True,
            "operation": "disable",
            "accountPurpose": "client-owner",
            "sessionVersion": 8,
            "enabled": False,
        }
        expected_request = json.dumps(
            {
                "contractVersion": 1,
                "operation": "disable",
                "username": OWNER_EMAIL,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        with patch.object(
            owner,
            "_signed_function_url_post",
            return_value=(
                200,
                {
                    "content-type": "application/json; charset=utf-8",
                    "cache-control": "no-store, max-age=0",
                },
                json.dumps(response_payload).encode("utf-8"),
            ),
        ) as signed_post:
            result = owner.invoke_owner_operator(
                session,
                operation="disable",
                username=OWNER_EMAIL,
            )

        self.assertEqual(session.client_names, ["sts", "lambda"])
        self.assertEqual(result["operation"], "disable")
        self.assertEqual(
            lambda_client.calls,
            [{
                "FunctionName": owner.APPROVED_MEDIATOR_FUNCTION,
                "Qualifier": owner.APPROVED_MEDIATOR_QUALIFIER,
            }],
        )
        signed_post.assert_called_once_with(session, FUNCTION_URL, expected_request)

    def test_signed_transport_rejects_every_non_lambda_url_before_network_io(self):
        session = RecordingSession()
        modules, records = fake_botocore_modules(object())

        with patch.dict(sys.modules, modules):
            with self.assertRaises(owner.OwnerOperationError):
                owner._signed_function_url_post(
                    session,
                    "https://example.invalid/",
                    b'{}',
                )

        self.assertEqual(session.credential_reads, 0)
        self.assertEqual(records, {})

    def test_signed_transport_posts_sigv4_json_and_returns_bounded_response(self):
        session = RecordingSession()
        response = type(
            "Response",
            (),
            {
                "status_code": 200,
                "headers": {
                    "Content-Type": "application/json; charset=utf-8",
                    "Cache-Control": "no-store, max-age=0",
                },
                "content": b'{"ok":true}',
            },
        )()
        payload = b'{"contractVersion":1}'
        modules, records = fake_botocore_modules(response)

        with patch.dict(sys.modules, modules):
            result = owner._signed_function_url_post(session, FUNCTION_URL, payload)

        self.assertEqual(records["timeout"], 65)
        self.assertEqual(
            records["signer"],
            ("synthetic-frozen-credentials", "lambda", "us-east-1"),
        )
        prepared = records["prepared"]
        self.assertEqual(prepared.method, "POST")
        self.assertEqual(prepared.url, FUNCTION_URL)
        self.assertEqual(prepared.body, payload)
        self.assertEqual(prepared.headers["content-type"], "application/json")
        self.assertTrue(prepared.headers["Authorization"].startswith("AWS4-HMAC-SHA256"))
        self.assertEqual(
            result,
            (
                200,
                {
                    "content-type": "application/json; charset=utf-8",
                    "cache-control": "no-store, max-age=0",
                },
                b'{"ok":true}',
            ),
        )

    def test_rejected_cli_arguments_never_echo_a_mistaken_password(self):
        repository_root = pathlib.Path(__file__).resolve().parents[1]
        sentinel = "Private-Arg-Sentinel-8472!"
        completed = subprocess.run(
            [
                sys.executable,
                "tools/provision_thn_owner.py",
                "create",
                "--temporary-password",
                sentinel,
            ],
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertNotIn(sentinel, completed.stderr)
        self.assertIn("invalid arguments", completed.stderr)

    def test_account_anchor_is_code_owned_and_has_no_env_or_function_selector(self):
        source = inspect.getsource(owner)
        self.assertNotIn("THN_OWNER_OPERATOR_ACCOUNT_ID", source)
        self.assertNotIn(
            "trusted_account_id",
            inspect.signature(owner.execute_operation).parameters,
        )

        original = owner.APPROVED_AWS_ACCOUNT_ID_SHA256
        try:
            owner.APPROVED_AWS_ACCOUNT_ID_SHA256 = hashlib.sha256(
                b"999999999999"
            ).hexdigest()
            with self.assertRaises(owner.OperatorAuthorizationError):
                owner.execute_operation(
                    RecordingSession(),
                    state_client=RecordingCurrentUserStateClient(),
                    operation="repair-session-version",
                    username=OWNER_EMAIL,
                    event_sink=lambda _event: None,
                )
        finally:
            owner.APPROVED_AWS_ACCOUNT_ID_SHA256 = original


class ThnOwnerDiscoveryTests(unittest.TestCase):
    def test_discovers_one_exact_secure_thn_pool_client_and_owner_group(self):
        cognito = RecordingCognitoClient()

        stack = RecordingCloudFormationClient()
        resources = owner.discover_dedicated_resources(cognito, stack)

        self.assertEqual(
            resources,
            {
                "userPoolId": USER_POOL_ID,
                "clientId": CLIENT_ID,
                "groupName": "journal-owner",
            },
        )
        self.assertEqual(calls_for(cognito, "describe_user_pool"), [{"UserPoolId": USER_POOL_ID}])
        self.assertEqual(
            calls_for(cognito, "describe_user_pool_client"),
            [{"UserPoolId": USER_POOL_ID, "ClientId": CLIENT_ID}],
        )
        self.assertEqual(
            stack.calls,
            [
                {
                    "StackName": "zoolanding-auth-admin-test",
                    "LogicalResourceId": "ThnAuthAdminV2UserPool",
                },
                {
                    "StackName": "zoolanding-auth-admin-test",
                    "LogicalResourceId": "ThnAuthAdminV2UserPoolClient",
                },
                {
                    "StackName": "zoolanding-auth-admin-test",
                    "LogicalResourceId": "ThnAuthAdminV2OwnerGroup",
                },
            ],
        )

        self.assertEqual(
            calls_for(cognito, "get_group"),
            [{"UserPoolId": USER_POOL_ID, "GroupName": "journal-owner"}],
        )
        self.assertEqual(calls_for(cognito, "list_user_pools"), [])
        self.assertEqual(calls_for(cognito, "list_user_pool_clients"), [])
        self.assertEqual(calls_for(cognito, "list_groups"), [])

    def test_missing_or_drifted_stack_resource_fails_closed(self):
        cases = (
            RecordingCognitoClient(described_pool=secure_pool(name="other-pool")),
            RecordingCognitoClient(described_pool=secure_pool(pool_id="us-east-1_OtherPool")),
            RecordingCognitoClient(described_client=dedicated_client(name="other-client")),
            RecordingCognitoClient(described_client=dedicated_client(client_id="other-client")),
            RecordingCognitoClient(groups=[]),
            RecordingCognitoClient(
                groups=[{"GroupName": "journal-owner"}, {"GroupName": "journal-owner"}]
            ),
        )

        for cognito in cases:
            with self.subTest(calls=cognito.calls):
                with self.assertRaises(owner.OwnerProvisioningError):
                    owner.discover_dedicated_resources(
                        cognito,
                        RecordingCloudFormationClient(),
                    )

    def test_zoosite_shaped_pool_client_or_group_never_matches(self):
        cases = (
            (
                RecordingCognitoClient(
                    described_pool=secure_pool(name="zoolanding-auth-admin-test-ZoositeUserPool")
                ),
                RecordingCloudFormationClient(),
            ),
            (
                RecordingCognitoClient(),
                RecordingCloudFormationClient(pool_id="us-east-1_zoositeLegacy"),
            ),
            (
                RecordingCognitoClient(
                    described_client=dedicated_client(
                        name="zoolanding-auth-admin-test-ZoositeClient"
                    )
                ),
                RecordingCloudFormationClient(),
            ),
            (
                RecordingCognitoClient(),
                RecordingCloudFormationClient(client_id="zoosite-client"),
            ),
            (
                RecordingCognitoClient(groups=[{"GroupName": "zoosite-admin"}]),
                RecordingCloudFormationClient(),
            ),
        )

        for cognito, stack in cases:
            with self.subTest(cognito=cognito):
                with self.assertRaises(owner.OwnerProvisioningError):
                    owner.discover_dedicated_resources(
                        cognito,
                        stack,
                    )

    def test_pool_must_be_admin_create_only_totp_only_and_trigger_free(self):
        insecure_pools = (
            secure_pool(AdminCreateUserConfig={"AllowAdminCreateUserOnly": False}),
            secure_pool(MfaConfiguration="OFF"),
            secure_pool(EnabledMfas=[]),
            secure_pool(EnabledMfas=["SMS_MFA", "SOFTWARE_TOKEN_MFA"]),
            secure_pool(LambdaConfig={"PostAuthentication": "legacy-lifecycle-arn"}),
            secure_pool(AccountRecoverySetting={
                "RecoveryMechanisms": [{"Priority": 1, "Name": "verified_email"}],
            }),
        )

        for pool in insecure_pools:
            cognito = RecordingCognitoClient(described_pool=pool)
            with self.subTest(pool=pool):
                with self.assertRaises(owner.OwnerProvisioningError):
                    owner.discover_dedicated_resources(
                        cognito,
                        RecordingCloudFormationClient(),
                    )

    def test_client_must_keep_the_five_minute_auth_session_contract(self):
        for value in (None, 4, 6, 99, "5"):
            with self.subTest(auth_session_validity=value):
                client = dedicated_client(AuthSessionValidity=value)
                with self.assertRaises(owner.OwnerProvisioningError):
                    owner.discover_dedicated_resources(
                        RecordingCognitoClient(described_client=client),
                        RecordingCloudFormationClient(),
                    )

    def test_already_disabled_reset_still_revokes_the_previous_session_version(self):
        state_client = owner.DynamoCurrentUserStateClient(object())
        current = {
            "subject": SUBJECT,
            "accountPurpose": "client-owner",
            "sessionVersion": 8,
            "enabled": False,
        }
        state_client._load = lambda _subject: dict(current)
        expected = {**current, "sessionVersion": 9}

        with (
            patch.object(owner, "disable_current_user_state") as disable,
            patch.object(
                owner,
                "repair_current_user_session_version",
                return_value=expected,
            ) as repair,
        ):
            result = state_client.reset(
                subject=SUBJECT,
                account_purpose="client-owner",
            )

        disable.assert_not_called()
        repair.assert_called_once_with(
            state_client._dynamodb,
            scope=owner.APPROVED_SCOPE,
            subject=SUBJECT,
            account_purpose="client-owner",
            session_version=8,
            enabled=False,
        )
        self.assertEqual(result, expected)

    def test_stack_physical_ids_must_match_the_unique_cognito_resources(self):
        cognito = RecordingCognitoClient()
        for stack in (
            RecordingCloudFormationClient(pool_id="us-east-1_OtherPool"),
            RecordingCloudFormationClient(client_id="other-client"),
        ):
            with self.subTest(stack=stack):
                with self.assertRaises(owner.OwnerProvisioningError):
                    owner.discover_dedicated_resources(cognito, stack)

    def test_group_must_be_the_exact_stack_owned_group(self):
        stack = RecordingCloudFormationClient()
        stack.physical_ids["ThnAuthAdminV2OwnerGroup"] = "other-group"

        with self.assertRaises(owner.OwnerProvisioningError):
            owner.discover_dedicated_resources(RecordingCognitoClient(), stack)


class ThnOwnerMutationTests(unittest.TestCase):
    def execute(self, operation, *, cognito=None, state=None, temporary_password=None):
        session = RecordingSession(
            cognito=cognito
            or RecordingCognitoClient(
                user_exists_before_create=operation != "create"
            )
        )
        state_client = state or RecordingCurrentUserStateClient()
        events = []
        result = owner.execute_operation(
            session,
            state_client=state_client,
            operation=operation,
            username=OWNER_EMAIL,
            temporary_password=temporary_password,
            event_sink=events.append,
        )
        return result, session, state_client, events

    def test_create_requires_temporary_password_and_assigns_only_client_owner(self):
        session = RecordingSession()
        state = RecordingCurrentUserStateClient()
        with self.assertRaises(owner.OperatorInputError):
            owner.execute_operation(
                session,
                state_client=state,
                operation="create",
                username=OWNER_EMAIL,
            )
        self.assertEqual(session.client_names, ["sts"])
        self.assertEqual(state.calls, [])

        result, session, state, _events = self.execute(
            "create", temporary_password=TEMPORARY_PASSWORD
        )
        cognito = session.cognito
        create = calls_for(cognito, "admin_create_user")[-1]
        self.assertEqual(
            create,
            {
                "UserPoolId": USER_POOL_ID,
                "Username": OWNER_EMAIL,
                "TemporaryPassword": TEMPORARY_PASSWORD,
                "MessageAction": "SUPPRESS",
                "UserAttributes": [
                    {"Name": "email", "Value": OWNER_EMAIL},
                    {"Name": "email_verified", "Value": "true"},
                ],
            },
        )
        self.assertEqual(
            calls_for(cognito, "admin_add_user_to_group"),
            [{
                "UserPoolId": USER_POOL_ID,
                "Username": COGNITO_USERNAME,
                "GroupName": "journal-owner",
            }],
        )
        self.assertEqual(
            state.calls,
            [("provision", {"subject": SUBJECT, "accountPurpose": "client-owner"})],
        )
        self.assertEqual(result["accountPurpose"], "client-owner")
        self.assertEqual(result["sessionVersion"], 1)
        self.assertFalse(result["enabled"])

    def test_each_operation_appends_intent_before_mutation_and_completed_afterward(self):
        result, _session, _state, events = self.execute(
            "create", temporary_password=TEMPORARY_PASSWORD
        )

        self.assertEqual([event["phase"] for event in events], ["intent", "completed"])
        self.assertEqual(events[0]["operationId"], events[1]["operationId"])
        self.assertEqual(events[0]["operation"], "create")
        self.assertNotIn("sessionVersion", events[0])
        self.assertEqual(events[1]["sessionVersion"], result["sessionVersion"])

    def test_intent_audit_failure_prevents_every_owner_mutation(self):
        session = RecordingSession()
        state = RecordingCurrentUserStateClient()
        sink = FailingEventSink(fail_on_call=1)

        with self.assertRaises(owner.OwnerOperationError):
            owner.execute_operation(
                session,
                state_client=state,
                operation="disable",
                username=OWNER_EMAIL,
                event_sink=sink,
            )

        self.assertEqual(state.calls, [])
        mutating = {
            "admin_create_user",
            "admin_add_user_to_group",
            "admin_enable_user",
            "admin_disable_user",
            "admin_user_global_sign_out",
            "admin_set_user_password",
            "admin_delete_software_token",
        }
        self.assertFalse(any(name in mutating for name, _kwargs in session.cognito.calls))

    def test_completed_audit_failure_leaves_a_durable_intent_for_reconciliation(self):
        session = RecordingSession()
        state = RecordingCurrentUserStateClient(
            {
                "subject": SUBJECT,
                "accountPurpose": "client-owner",
                "sessionVersion": 1,
                "enabled": False,
            }
        )
        sink = FailingEventSink(fail_on_call=2)

        with self.assertRaises(owner.OwnerOperationError):
            owner.execute_operation(
                session,
                state_client=state,
                operation="enable",
                username=OWNER_EMAIL,
                event_sink=sink,
            )

        self.assertTrue(state.state["enabled"])
        self.assertEqual(sink.events[0]["phase"], "intent")
        self.assertEqual(sink.events[0]["operationId"], sink.events[1]["operationId"])

    def test_enable_is_an_explicit_versioned_transition_before_first_login(self):
        state = RecordingCurrentUserStateClient(
            {
                "subject": SUBJECT,
                "accountPurpose": "client-owner",
                "sessionVersion": 1,
                "enabled": False,
            }
        )

        result, session, state, _events = self.execute("enable", state=state)

        self.assertEqual(
            state.calls,
            [("enable", {"subject": SUBJECT, "accountPurpose": "client-owner"})],
        )
        self.assertTrue(result["enabled"])
        self.assertEqual(result["sessionVersion"], 2)
        self.assertEqual(calls_for(session.cognito, "admin_disable_user"), [])
        self.assertEqual(calls_for(session.cognito, "admin_set_user_password"), [])
        self.assertEqual(
            calls_for(session.cognito, "admin_enable_user"),
            [{"UserPoolId": USER_POOL_ID, "Username": COGNITO_USERNAME}],
        )

    def test_enable_reconciles_after_provider_failure_without_a_second_version_bump(self):
        state = RecordingCurrentUserStateClient(
            {
                "subject": SUBJECT,
                "accountPurpose": "client-owner",
                "sessionVersion": 1,
                "enabled": False,
            }
        )
        events = []
        with self.assertRaises(owner.OwnerOperationError):
            owner.execute_operation(
                RecordingSession(
                    cognito=RecordingCognitoClient(provider_error="admin_enable_user")
                ),
                state_client=state,
                operation="enable",
                username=OWNER_EMAIL,
                event_sink=events.append,
            )

        self.assertTrue(state.state["enabled"])
        self.assertEqual(state.state["sessionVersion"], 2)
        self.assertEqual([event["phase"] for event in events], ["intent", "failed"])

        result, _session, state, retry_events = self.execute("enable", state=state)
        self.assertEqual(result["sessionVersion"], 2)
        self.assertTrue(result["enabled"])
        self.assertEqual([event["phase"] for event in retry_events], ["intent", "completed"])

    def test_create_failure_after_provider_creation_disables_the_new_user(self):
        cognito = RecordingCognitoClient(user_exists_before_create=False)
        with self.assertRaises(owner.OwnerOperationError):
            self.execute(
                "create",
                cognito=cognito,
                state=FailingProvisionStateClient(),
                temporary_password=TEMPORARY_PASSWORD,
            )

        self.assertEqual(
            calls_for(cognito, "admin_disable_user"),
            [{"UserPoolId": USER_POOL_ID, "Username": COGNITO_USERNAME}],
        )

    def test_new_user_is_disabled_when_the_owner_group_is_already_occupied(self):
        cognito = RecordingCognitoClient(
            user_exists_before_create=False,
            preserve_users_in_group_on_create=True,
            users_in_group=[
                {
                    "Username": "existing-owner-handle",
                    "Attributes": [{"Name": "sub", "Value": "existing-owner-subject"}],
                }
            ],
        )
        state = RecordingCurrentUserStateClient()

        with self.assertRaises(owner.OwnerOperationError):
            self.execute(
                "create",
                cognito=cognito,
                state=state,
                temporary_password=TEMPORARY_PASSWORD,
            )

        self.assertEqual(state.calls, [])
        self.assertEqual(
            calls_for(cognito, "admin_disable_user"),
            [{"UserPoolId": USER_POOL_ID, "Username": COGNITO_USERNAME}],
        )

    def test_new_user_is_disabled_when_owner_group_lookup_fails(self):
        cognito = RecordingCognitoClient(
            user_exists_before_create=False,
            provider_error="list_users_in_group",
        )
        state = RecordingCurrentUserStateClient()

        with self.assertRaises(owner.OwnerOperationError):
            self.execute(
                "create",
                cognito=cognito,
                state=state,
                temporary_password=TEMPORARY_PASSWORD,
            )

        self.assertEqual(state.calls, [])
        self.assertEqual(
            calls_for(cognito, "admin_disable_user"),
            [{"UserPoolId": USER_POOL_ID, "Username": COGNITO_USERNAME}],
        )

    def test_create_response_loss_never_disables_an_ambiguously_owned_user(self):
        cognito = RecordingCognitoClient(
            user_exists_before_create=False,
            create_commits_then_raises=True,
        )
        state = RecordingCurrentUserStateClient()
        with self.assertRaises(owner.OwnerOperationError):
            self.execute(
                "create",
                cognito=cognito,
                state=state,
                temporary_password=TEMPORARY_PASSWORD,
            )

        self.assertEqual(len(calls_for(cognito, "admin_create_user")), 1)
        self.assertEqual(len(calls_for(cognito, "admin_get_user")), 2)
        self.assertEqual(state.calls, [])
        self.assertEqual(calls_for(cognito, "admin_add_user_to_group"), [])
        self.assertEqual(calls_for(cognito, "admin_remove_user_from_group"), [])
        self.assertEqual(calls_for(cognito, "admin_disable_user"), [])

    def test_existing_owner_state_failure_never_disables_the_existing_user(self):
        cognito = RecordingCognitoClient(user_exists_before_create=True)
        with self.assertRaises(owner.OwnerOperationError):
            self.execute(
                "create",
                cognito=cognito,
                state=FailingProvisionStateClient(),
                temporary_password=TEMPORARY_PASSWORD,
            )

        self.assertEqual(calls_for(cognito, "admin_create_user"), [])
        self.assertEqual(calls_for(cognito, "admin_disable_user"), [])

    def test_create_reconciles_an_existing_partial_owner_instead_of_stranding_it(self):
        state = RecordingCurrentUserStateClient(owner_subject=SUBJECT)
        state.state = {
            "subject": SUBJECT,
            "accountPurpose": "client-owner",
            "sessionVersion": 1,
            "enabled": False,
        }
        cognito = RecordingCognitoClient(
            username_exists_on_create=True,
            user_groups=[],
            users_in_group=[],
        )

        result, session, state, events = self.execute(
            "create",
            cognito=cognito,
            state=state,
            temporary_password=TEMPORARY_PASSWORD,
        )

        self.assertFalse(result["enabled"])
        self.assertEqual(calls_for(session.cognito, "admin_get_user")[0]["Username"], OWNER_EMAIL)
        self.assertEqual(len(calls_for(session.cognito, "admin_add_user_to_group")), 1)
        self.assertEqual([event["phase"] for event in events], ["intent", "completed"])

    def test_second_distinct_owner_is_rejected_by_the_durable_singleton(self):
        shared_state = RecordingCurrentUserStateClient()
        self.execute(
            "create",
            state=shared_state,
            temporary_password=TEMPORARY_PASSWORD,
        )
        second = RecordingCognitoClient(
            provider_username="second-owner-handle",
            subject="second-owner-subject",
            email="second@example.test",
            user_exists_before_create=False,
        )

        with self.assertRaises(owner.OwnerOperationError):
            owner.execute_operation(
                RecordingSession(cognito=second),
                state_client=shared_state,
                operation="create",
                username="second@example.test",
                temporary_password=TEMPORARY_PASSWORD,
                event_sink=lambda _event: None,
            )

        self.assertEqual(shared_state.owner_subject, SUBJECT)
        self.assertEqual(len(calls_for(second, "admin_disable_user")), 1)

    def test_existing_user_requires_exact_owner_group_before_state_mutation(self):
        for groups in ([], [{"GroupName": "journal-owner"}, {"GroupName": "other"}]):
            with self.subTest(groups=groups):
                cognito = RecordingCognitoClient(user_groups=groups)
                state = RecordingCurrentUserStateClient(
                    {
                        "subject": SUBJECT,
                        "accountPurpose": "client-owner",
                        "sessionVersion": 1,
                        "enabled": False,
                    }
                )
                with self.assertRaises(owner.OwnerOperationError):
                    self.execute("enable", cognito=cognito, state=state)
                self.assertEqual(state.calls, [])

    def test_existing_user_requires_singleton_membership_of_the_owner_group(self):
        cognito = RecordingCognitoClient(
            users_in_group=[
                {"Username": COGNITO_USERNAME, "Attributes": [{"Name": "sub", "Value": SUBJECT}]},
                {"Username": "second-owner", "Attributes": [{"Name": "sub", "Value": "second-sub"}]},
            ]
        )
        state = RecordingCurrentUserStateClient(
            {
                "subject": SUBJECT,
                "accountPurpose": "client-owner",
                "sessionVersion": 1,
                "enabled": False,
            }
        )

        with self.assertRaises(owner.OwnerOperationError):
            self.execute("enable", cognito=cognito, state=state)

        self.assertEqual(state.calls, [])

    def test_disable_can_invalidate_state_after_owner_group_drift(self):
        cognito = RecordingCognitoClient(user_groups=[], users_in_group=[])

        result, _, state, _ = self.execute("disable", cognito=cognito)

        self.assertFalse(result["enabled"])
        self.assertEqual(result["sessionVersion"], 8)
        self.assertEqual(
            state.calls,
            [("disable", {"subject": SUBJECT, "accountPurpose": "client-owner"})],
        )

    def test_disable_revokes_cognito_and_advances_current_session_version(self):
        result, session, state, _events = self.execute("disable")
        cognito = session.cognito

        self.assertEqual(
            calls_for(cognito, "admin_disable_user"),
            [{"UserPoolId": USER_POOL_ID, "Username": COGNITO_USERNAME}],
        )
        self.assertEqual(
            calls_for(cognito, "admin_user_global_sign_out"),
            [{"UserPoolId": USER_POOL_ID, "Username": COGNITO_USERNAME}],
        )
        self.assertEqual(
            state.calls,
            [("disable", {"subject": SUBJECT, "accountPurpose": "client-owner"})],
        )
        self.assertFalse(result["enabled"])
        self.assertEqual(result["sessionVersion"], 8)

    def test_disable_is_retriable_when_state_is_already_disabled(self):
        state = RecordingCurrentUserStateClient(
            {
                "subject": SUBJECT,
                "accountPurpose": "client-owner",
                "sessionVersion": 8,
                "enabled": False,
            }
        )

        result, session, state, events = self.execute("disable", state=state)

        self.assertFalse(result["enabled"])
        self.assertEqual(result["sessionVersion"], 8)
        self.assertEqual(len(calls_for(session.cognito, "admin_disable_user")), 1)
        self.assertEqual([event["phase"] for event in events], ["intent", "completed"])

    def test_disable_reconciles_after_signout_failure(self):
        state = RecordingCurrentUserStateClient()
        events = []
        with self.assertRaises(owner.OwnerOperationError):
            owner.execute_operation(
                RecordingSession(
                    cognito=RecordingCognitoClient(provider_error="admin_user_global_sign_out")
                ),
                state_client=state,
                operation="disable",
                username=OWNER_EMAIL,
                event_sink=events.append,
            )

        self.assertFalse(state.state["enabled"])
        self.assertEqual([event["phase"] for event in events], ["intent", "failed"])

        result, session, _state, retry_events = self.execute("disable", state=state)
        self.assertFalse(result["enabled"])
        self.assertEqual(len(calls_for(session.cognito, "admin_disable_user")), 1)
        self.assertEqual([event["phase"] for event in retry_events], ["intent", "completed"])

    def test_reset_requires_new_password_deletes_totp_and_leaves_owner_disabled(self):
        result, session, state, _events = self.execute(
            "reset", temporary_password=TEMPORARY_PASSWORD
        )
        cognito = session.cognito

        self.assertEqual(
            calls_for(cognito, "admin_set_user_password"),
            [{
                "UserPoolId": USER_POOL_ID,
                "Username": COGNITO_USERNAME,
                "Password": TEMPORARY_PASSWORD,
                "Permanent": False,
            }],
        )
        self.assertEqual(
            calls_for(cognito, "admin_delete_software_token"),
            [{"UserPoolId": USER_POOL_ID, "Username": COGNITO_USERNAME}],
        )
        self.assertEqual(calls_for(cognito, "admin_set_user_mfa_preference"), [])
        self.assertEqual(len(calls_for(cognito, "admin_user_global_sign_out")), 1)
        self.assertEqual(len(calls_for(cognito, "admin_disable_user")), 1)
        self.assertEqual(calls_for(cognito, "admin_enable_user"), [])
        self.assertEqual(
            state.calls,
            [("reset", {"subject": SUBJECT, "accountPurpose": "client-owner"})],
        )
        self.assertEqual(result["sessionVersion"], 8)
        self.assertFalse(result["enabled"])

        mutation_order = [name for name, _kwargs in cognito.calls]
        self.assertLess(
            mutation_order.index("admin_disable_user"),
            mutation_order.index("admin_set_user_password"),
        )
        self.assertLess(
            mutation_order.index("admin_set_user_password"),
            mutation_order.index("admin_delete_software_token"),
        )

    def test_reset_password_failure_keeps_cognito_and_state_disabled_with_totp_intact(self):
        cognito = RecordingCognitoClient(provider_error="admin_set_user_password")
        state = RecordingCurrentUserStateClient()

        with self.assertRaises(owner.OwnerOperationError):
            self.execute(
                "reset",
                cognito=cognito,
                state=state,
                temporary_password=TEMPORARY_PASSWORD,
            )

        self.assertFalse(state.state["enabled"])
        self.assertEqual(len(calls_for(cognito, "admin_disable_user")), 1)
        self.assertEqual(calls_for(cognito, "admin_delete_software_token"), [])
        self.assertEqual(calls_for(cognito, "admin_enable_user"), [])

        retry, _, _, _ = self.execute(
            "reset",
            state=state,
            temporary_password=TEMPORARY_PASSWORD,
        )
        self.assertEqual(retry["sessionVersion"], 8)
        self.assertFalse(retry["enabled"])

    def test_reset_state_failure_happens_before_any_cognito_mutation(self):
        state = RecordingCurrentUserStateClient()

        def fail_reset(*, subject, account_purpose):
            state.calls.append(
                ("reset", {"subject": subject, "accountPurpose": account_purpose})
            )
            raise RuntimeError("state write failed")

        state.reset = fail_reset
        cognito = RecordingCognitoClient(user_exists_before_create=True)

        with self.assertRaises(owner.OwnerOperationError):
            self.execute(
                "reset",
                cognito=cognito,
                state=state,
                temporary_password=TEMPORARY_PASSWORD,
            )

        mutating = {
            "admin_disable_user",
            "admin_user_global_sign_out",
            "admin_set_user_password",
            "admin_delete_software_token",
        }
        self.assertEqual(
            [name for name, _kwargs in cognito.calls if name in mutating],
            [],
        )

    def test_repair_advances_only_session_version_and_never_changes_purpose_or_group(self):
        result, session, state, _events = self.execute("repair-session-version")

        self.assertEqual(
            state.calls,
            [("repair_session_version", {
                "subject": SUBJECT,
                "accountPurpose": "client-owner",
            })],
        )
        self.assertEqual(result["accountPurpose"], "client-owner")
        self.assertEqual(result["sessionVersion"], 8)
        self.assertEqual(calls_for(session.cognito, "admin_add_user_to_group"), [])
        self.assertEqual(calls_for(session.cognito, "admin_disable_user"), [])

    def test_no_operation_constructs_or_invokes_the_lifecycle_service(self):
        for operation, password in (
            ("create", TEMPORARY_PASSWORD),
            ("enable", None),
            ("disable", None),
            ("reset", TEMPORARY_PASSWORD),
            ("repair-session-version", None),
        ):
            with self.subTest(operation=operation):
                state = None
                if operation == "enable":
                    state = RecordingCurrentUserStateClient(
                        {
                            "subject": SUBJECT,
                            "accountPurpose": "client-owner",
                            "sessionVersion": 1,
                            "enabled": False,
                        }
                    )
                _result, session, _state, _events = self.execute(
                    operation,
                    temporary_password=password,
                    state=state,
                )
                self.assertEqual(
                    session.client_names,
                    ["sts", "cloudformation", "cognito-idp"],
                )
                self.assertNotIn("lambda", session.client_names)

        source = inspect.getsource(owner).lower()
        core_source = inspect.getsource(owner.execute_operation).lower()
        self.assertNotIn("zoolanding-cognito-user-lifecycle", source)
        self.assertNotIn("client(\"lambda\")", core_source)
        self.assertFalse(hasattr(owner, "lambda_handler"))

    def test_results_events_and_provider_errors_do_not_expose_pii_or_secrets(self):
        result, _session, _state, events = self.execute(
            "create", temporary_password=TEMPORARY_PASSWORD
        )
        safe_text = json.dumps({"result": result, "events": events}, sort_keys=True)
        for private_value in (
            OWNER_EMAIL,
            TEMPORARY_PASSWORD,
            USER_POOL_ID,
            CLIENT_ID,
            COGNITO_USERNAME,
            SUBJECT,
        ):
            self.assertNotIn(private_value, safe_text)

        failing = RecordingCognitoClient(
            provider_error="admin_create_user",
            user_exists_before_create=False,
        )
        with self.assertRaises(owner.OwnerOperationError) as caught:
            self.execute(
                "create",
                cognito=failing,
                temporary_password=TEMPORARY_PASSWORD,
            )
        error_text = str(caught.exception)
        self.assertNotIn(OWNER_EMAIL, error_text)
        self.assertNotIn(TEMPORARY_PASSWORD, error_text)
        self.assertNotIn(USER_POOL_ID, error_text)


if __name__ == "__main__":
    unittest.main()
