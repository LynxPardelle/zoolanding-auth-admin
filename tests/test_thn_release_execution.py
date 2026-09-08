"""Exercise the release transaction against in-memory AWS service doubles."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tests.test_thn_test_release import ACCOUNT, ACCOUNT_HASH, PREFIX, stack, templates
from tests.test_prepare_thn_test_parameters import selection

ROOT = Path(__file__).resolve().parents[1]


class Waiter:
    def wait(self, **kwargs):
        return None


class CloudFormation:
    def __init__(self):
        self.stack = stack()
        self.template, self.candidate = templates()
        self.executed = False
        self.deleted = False
        self.drift = False
        self.change_parameters = []

    def describe_stacks(self, **kwargs):
        return {"Stacks": [deepcopy(self.stack)]}

    def get_template(self, **kwargs):
        return {"TemplateBody": deepcopy(self.template)}

    def list_stack_resources(self, **kwargs):
        resources = [{"LogicalResourceId": "AuthAdminFunction", "PhysicalResourceId": "existing-v1",
                      "ResourceType": "AWS::Lambda::Function", "ResourceStatus": "UPDATE_COMPLETE"}]
        values = {p['ParameterKey']: p['ParameterValue'] for p in self.stack['Parameters']}
        if values.get('ProvisionThnAuthAdminV2State') == 'true':
            resources.append({"LogicalResourceId": PREFIX + "SessionTable", "PhysicalResourceId": "example-session-table",
                              "ResourceType": "AWS::DynamoDB::Table", "ResourceStatus": "CREATE_COMPLETE"})
        if values.get('ProvisionThnAuthAdminV2State') == 'true':
            resources.append({"LogicalResourceId": PREFIX + "Function", "PhysicalResourceId": "example-private-function",
                              "ResourceType": "AWS::Lambda::Function", "ResourceStatus": "CREATE_COMPLETE"})
        return {"StackResourceSummaries": resources}

    def create_change_set(self, **kwargs):
        self.change_parameters = deepcopy(kwargs["Parameters"])
        self.name = kwargs["ChangeSetName"]
        self.arn = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:changeSet/{self.name}/example"
        return {"Id": self.arn}

    def get_waiter(self, name):
        return Waiter()

    def describe_change_set(self, **kwargs):
        current = {p["ParameterKey"]: p["ParameterValue"] for p in self.stack["Parameters"]}
        for p in self.change_parameters:
            if "ParameterValue" in p:
                current[p["ParameterKey"]] = p["ParameterValue"]
        return {"StackName": self.stack["StackName"], "ChangeSetId": self.arn, "ChangeSetName": self.name,
                "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE",
                "Parameters": [{"ParameterKey": k, "ParameterValue": v} for k, v in current.items()],
                "Changes": [{"Type": "Resource", "ResourceChange": {"Action": "Add", "Replacement": "False",
                    "ResourceType": "AWS::DynamoDB::Table", "LogicalResourceId": "AuthAdminFunction" if self.drift else PREFIX + "SessionTable"}}]}

    def execute_change_set(self, **kwargs):
        self.executed = True
        values = {p["ParameterKey"]: p["ParameterValue"] for p in self.stack["Parameters"]}
        values.update({p["ParameterKey"]: p["ParameterValue"] for p in self.change_parameters if "ParameterValue" in p})
        self.stack["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in values.items()]

    def delete_change_set(self, **kwargs):
        self.deleted = True


class Storage:
    def __init__(self):
        self.objects = []

    def put_object(self, **kwargs):
        self.objects.append(kwargs)


class DynamoDB:
    def describe_table(self, **kwargs):
        return {"Table": {"TableStatus": "ACTIVE", "DeletionProtectionEnabled": True,
                          "SSEDescription": {"Status": "ENABLED"}}}

    def describe_continuous_backups(self, **kwargs):
        return {"ContinuousBackupsDescription": {"PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED"}}}


class Session:
    def __init__(self):
        self.cfn = CloudFormation()
        self.s3 = Storage()
        self.clients = []

    def client(self, name, **kwargs):
        self.clients.append(name)
        if name == "sts":
            return self
        return {"cloudformation": self.cfn, "s3": self.s3, "dynamodb": DynamoDB()}[name]

    def get_caller_identity(self):
        return {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/example-test-release/example"}


def environment():
    return {"GITHUB_REPOSITORY": "LynxPardelle/zoolanding-auth-admin", "GITHUB_REF": "refs/heads/test",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": "a" * 40, "EXPECTED_SOURCE_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "AWS_REGION": "us-east-1",
            "AWS_DEFAULT_REGION": "us-east-1", "ARTIFACTS_BUCKET": "example-test-artifacts"}


class ReleaseExecutionTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "tools/thn_test_release.py"
        spec = importlib.util.spec_from_file_location("release_execution", path)
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)
        self.assertTrue(hasattr(self.tool, "run_release"), "Dedicated release transaction is missing")

    def run_release(self, session, env=None, operation="provision"):
        with TemporaryDirectory() as temp, patch.object(self.tool, "ACCOUNT_HASH", ACCOUNT_HASH), \
                patch.object(self.tool, "_package_template", return_value=session.cfn.candidate), \
                patch.object(self.tool.time, "sleep"):
            return self.tool.run_release(session, environment() if env is None else env, Path(temp), operation)

    def test_provision_executes_only_thn_change_and_retains_shared_values(self):
        session = Session()
        result = self.run_release(session)
        self.assertTrue(session.cfn.executed)
        self.assertEqual(result["operation"], "provision")
        self.assertTrue(result["retained_state_verified"])
        uploaded = json.loads(session.s3.objects[0]["Body"])
        self.assertEqual(uploaded["Resources"]["AuthAdminFunction"], session.cfn.template["Resources"]["AuthAdminFunction"])
        self.assertEqual(session.s3.objects[0]["ServerSideEncryption"], "AES256")
        self.assertNotIn(ACCOUNT, json.dumps(result))

    def test_wrong_context_never_reads_or_writes_aws(self):
        session = Session()
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.run_release(session, {**environment(), "GITHUB_REF": "refs/heads/main"})
        self.assertEqual(session.clients, [])

    def test_missing_termination_protection_never_creates_a_change_set(self):
        session = Session()
        session.cfn.stack["EnableTerminationProtection"] = False
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.run_release(session)
        self.assertEqual(session.cfn.change_parameters, [])
        self.assertEqual(session.s3.objects, [])

    def test_shared_resource_change_is_rejected_before_execution(self):
        session = Session()
        session.cfn.drift = True
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.run_release(session)
        self.assertFalse(session.cfn.executed)
        self.assertTrue(session.cfn.deleted)

    def test_enable_requires_protected_existing_state_and_never_changes_shared_parameters(self):
        session = Session()
        session.cfn.stack = stack(state=True)
        session.cfn.template = deepcopy(session.cfn.candidate)
        result = self.run_release(session, {**environment(), "THN_V2_TEST_PARAMETERS_JSON": json.dumps(selection())}, "enable")
        self.assertEqual(result["operation"], "enable")
        current = {p["ParameterKey"]: p["ParameterValue"] for p in session.cfn.stack["Parameters"]}
        self.assertEqual(current["EnableThnAuthAdminV2"], "true")
        self.assertEqual(current["AuthAdminConfigJsonBase64"], "****")

    def test_disable_preserves_live_template_and_does_not_package_new_code(self):
        session = Session()
        session.cfn.stack = stack(enabled=True, state=True)
        session.cfn.template = deepcopy(session.cfn.candidate)
        with TemporaryDirectory() as temp, patch.object(self.tool, "ACCOUNT_HASH", ACCOUNT_HASH), \
                patch.object(self.tool, "_package_template", side_effect=AssertionError("disable must not rebuild code")), \
                patch.object(self.tool.time, "sleep"):
            result = self.tool.run_release(session, environment(), Path(temp), "disable")
        current = {p["ParameterKey"]: p["ParameterValue"] for p in session.cfn.stack["Parameters"]}
        self.assertEqual(current["EnableThnAuthAdminV2"], "false")
        self.assertEqual(current["ProvisionThnAuthAdminV2State"], "true")
        self.assertEqual(json.loads(session.s3.objects[0]["Body"]), session.cfn.template)
        self.assertEqual(result["operation"], "disable")


if __name__ == "__main__":
    unittest.main()
