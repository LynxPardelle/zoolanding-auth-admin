"""Offline release-boundary contracts; no AWS writes or credentials."""

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

from tools import provision_thn_owner as owner
from tests.test_prepare_thn_test_parameters import environment, selection

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "123456789012"
ACCOUNT_HASH = hashlib.sha256(ACCOUNT.encode()).hexdigest()
PREFIX = "ThnAuthAdminV2"


def stack(enabled=False, state=False):
    values = {"EnvironmentName": "test", "AuthAdminConfigJsonBase64": "****",
              "CognitoUserPoolArns": "not-returned", "LogLevel": "INFO",
              "EnableThnAuthAdminV2": str(enabled).lower(),
              "ProvisionThnAuthAdminV2State": str(state).lower()}
    return {
        "StackName": "zoolanding-auth-admin-test",
        "StackId": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/zoolanding-auth-admin-test/example",
        "StackStatus": "UPDATE_COMPLETE", "EnableTerminationProtection": True,
        "Parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in values.items()],
    }


def templates():
    old = {
        "AWSTemplateFormatVersion": "2010-09-09", "Transform": "AWS::Serverless-2016-10-31",
        "Globals": {"Function": {"Runtime": "python3.13"}},
        "Parameters": {"EnvironmentName": {"Type": "String"}, "AuthAdminConfigJsonBase64": {"Type": "String", "NoEcho": True}},
        "Resources": {"AuthAdminFunction": {"Type": "AWS::Serverless::Function", "Properties": {"CodeUri": "s3://existing/immutable", "Handler": "lambda_function.lambda_handler"}}},
        "Outputs": {"LegacyUrl": {"Value": "existing-value"}},
    }
    candidate = deepcopy(old)
    candidate["Resources"]["AuthAdminFunction"]["Properties"]["CodeUri"] = "s3://new/build"
    candidate["Resources"][PREFIX + "SessionTable"] = {
        "Type": "AWS::DynamoDB::Table", "Condition": "IsThnAuthAdminV2StateProvisioned",
        "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": {},
    }
    candidate["Conditions"] = {"IsThnAuthAdminV2StateProvisioned": {"Fn::Equals": ["test", "test"]}}
    candidate["Parameters"]["EnableThnAuthAdminV2"] = {"Type": "String", "Default": "false"}
    return old, candidate


class ThnTestReleaseTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "tools/thn_test_release.py"
        self.assertTrue(path.exists(), "Dedicated THN lifecycle release implementation is missing")
        spec = importlib.util.spec_from_file_location("thn_test_release", path)
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)

    def test_provision_keeps_runtime_closed_and_every_legacy_parameter_previous(self):
        result = self.tool.lifecycle_parameters(stack(), "provision", None)
        values = {p["ParameterKey"]: p for p in result}
        self.assertEqual(values["EnableThnAuthAdminV2"]["ParameterValue"], "false")
        self.assertEqual(values["ProvisionThnAuthAdminV2State"]["ParameterValue"], "true")
        for key in ("EnvironmentName", "AuthAdminConfigJsonBase64", "CognitoUserPoolArns", "LogLevel"):
            self.assertEqual(values[key], {"ParameterKey": key, "UsePreviousValue": True})
        self.assertNotIn("****", json.dumps(result))

    def test_enable_requires_preexisting_state_and_complete_selection(self):
        payload = environment()["THN_V2_TEST_PARAMETERS_JSON"]
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.lifecycle_parameters(stack(), "enable", payload)
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.lifecycle_parameters(stack(state=True), "enable", None)
        result = self.tool.lifecycle_parameters(stack(state=True), "enable", payload)
        self.assertEqual(next(p["ParameterValue"] for p in result if p["ParameterKey"] == "EnableThnAuthAdminV2"), "true")

    def test_disable_never_unprovisions_state_or_replaces_descriptor_and_proof(self):
        previous = stack(enabled=True, state=True)
        previous["Parameters"].extend({"ParameterKey": k, "ParameterValue": v}
                                      for k, v in selection()["parameters"].items()
                                      if k not in {"EnableThnAuthAdminV2", "ProvisionThnAuthAdminV2State"})
        result = self.tool.lifecycle_parameters(previous, "disable", None)
        values = {p["ParameterKey"]: p for p in result}
        self.assertEqual(values["ProvisionThnAuthAdminV2State"]["ParameterValue"], "true")
        self.assertEqual(values["EnableThnAuthAdminV2"]["ParameterValue"], "false")
        self.assertEqual(values["ThnAuthAdminV2OriginHeaderSha256Current"],
                         {"ParameterKey": "ThnAuthAdminV2OriginHeaderSha256Current", "UsePreviousValue": True})

    def test_provision_cannot_silently_disable_active_runtime(self):
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.lifecycle_parameters(stack(enabled=True, state=True), "provision", None)

    def test_enable_rejects_hidden_disable_or_state_removal(self):
        for key in ("EnableThnAuthAdminV2", "ProvisionThnAuthAdminV2State"):
            payload = selection()
            payload["parameters"][key] = "false"
            with self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.lifecycle_parameters(stack(state=True), "enable", json.dumps(payload))

    def test_preflight_requires_account_region_test_identity_and_real_termination_protection(self):
        self.tool.validate_stack(stack(), ACCOUNT, expected_account_hash=ACCOUNT_HASH)
        mutations = [
            {"EnableTerminationProtection": False}, {"StackStatus": "UPDATE_IN_PROGRESS"},
            {"StackName": "zoolanding-auth-admin-production"},
            {"StackId": stack()["StackId"].replace("us-east-1", "eu-west-1")},
            {"StackId": stack()["StackId"].replace(ACCOUNT, "999999999999")},
        ]
        for mutation in mutations:
            with self.subTest(fields=list(mutation)), self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.validate_stack({**stack(), **mutation}, ACCOUNT, expected_account_hash=ACCOUNT_HASH)
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.validate_stack(stack(), ACCOUNT, expected_account_hash="0" * 64)

    def test_preflight_rejects_duplicate_parameters_or_production_environment(self):
        for parameter in ({"ParameterKey": "EnvironmentName", "ParameterValue": "prod"},
                          {"ParameterKey": "EnvironmentName", "ParameterValue": "test"}):
            previous = stack()
            previous["Parameters"].append(parameter)
            with self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.validate_stack(previous, ACCOUNT, expected_account_hash=ACCOUNT_HASH)

    def test_composition_preserves_all_legacy_resources_and_outputs_exactly(self):
        old, candidate = templates()
        before = deepcopy(candidate)
        combined = self.tool.compose_template(candidate, old)
        self.assertEqual(combined["Resources"]["AuthAdminFunction"], old["Resources"]["AuthAdminFunction"])
        self.assertEqual(combined["Outputs"]["LegacyUrl"], old["Outputs"]["LegacyUrl"])
        self.assertIn(PREFIX + "SessionTable", combined["Resources"])
        self.assertEqual(candidate, before)

    def test_disable_uses_live_code_and_template_instead_of_candidate_resources(self):
        old, candidate = templates()
        combined = self.tool.compose_template(candidate, old, operation="disable")
        self.assertEqual(combined, old)

    def test_shared_globals_cannot_change(self):
        old, candidate = templates()
        candidate["Globals"]["Function"]["Runtime"] = "python3.14"
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.compose_template(candidate, old)

    def test_state_resources_must_be_retained_and_state_conditioned(self):
        for field, bad in (("DeletionPolicy", "Delete"), ("UpdateReplacePolicy", "Delete"),
                           ("Condition", "IsThnAuthAdminV2Enabled")):
            old, candidate = templates()
            candidate["Resources"][PREFIX + "SessionTable"][field] = bad
            with self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.compose_template(candidate, old)

    def test_changes_cannot_touch_legacy_replace_or_delete_retained_state(self):
        def change(logical, resource_type="AWS::Lambda::Function", action="Modify", replacement="False"):
            return {"Type": "Resource", "ResourceChange": {"LogicalResourceId": logical,
                    "ResourceType": resource_type, "Action": action, "Replacement": replacement}}
        self.tool.review_resources([change(PREFIX + "Function")], "enable")
        self.tool.review_resources([change(PREFIX + "Api", "AWS::ApiGatewayV2::Api", "Remove")], "disable")
        invalid = [change("AuthAdminFunction"), change(PREFIX + "Function", replacement="True"),
                   change(PREFIX + "Function", replacement="Conditional"),
                   change(PREFIX + "SessionTable", "AWS::DynamoDB::Table", "Remove"),
                   change(PREFIX + "UserPoolClient", "AWS::Cognito::UserPoolClient", "Remove"),
                   change(PREFIX + "FutureState", "AWS::S3::Bucket", "Remove")]
        for item in invalid:
            with self.subTest(resource=item["ResourceChange"]["LogicalResourceId"]), self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.review_resources([item], "disable")
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.review_resources([change(PREFIX + "Function", action="Remove")], "enable")

    def test_owner_account_anchor_is_bound_not_inert(self):
        self.assertNotEqual(owner.APPROVED_AWS_ACCOUNT_ID_SHA256, "0" * 64)
        self.assertRegex(owner.APPROVED_AWS_ACCOUNT_ID_SHA256, r"^[a-f0-9]{64}$")

    def test_execution_context_is_exact_test_repository_ref_sha_and_manual_event(self):
        self.assertTrue(hasattr(self.tool, "validate_context"), "Execution context guard is missing")
        env = {"GITHUB_REPOSITORY": "LynxPardelle/zoolanding-auth-admin", "GITHUB_REF": "refs/heads/test",
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": "a" * 40,
               "EXPECTED_SOURCE_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
               "AWS_REGION": "us-east-1", "AWS_DEFAULT_REGION": "us-east-1"}
        self.tool.validate_context(env)
        for key, value in (("GITHUB_REPOSITORY", "another/repo"), ("GITHUB_REF", "refs/heads/main"),
                           ("GITHUB_EVENT_NAME", "pull_request_target"), ("EXPECTED_SOURCE_SHA", "b" * 40),
                           ("GITHUB_SHA", "main"), ("GITHUB_RUN_ID", "../1"), ("AWS_REGION", "eu-west-1")):
            with self.subTest(field=key), self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.validate_context({**env, key: value})

    def test_review_binds_exact_update_identity_and_complete_parameter_values(self):
        self.assertTrue(hasattr(self.tool, "review_change_set"), "Dedicated change-set review is missing")
        arn = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:changeSet/thn-123-1/example"
        params = [{"ParameterKey": "EnvironmentName", "ParameterValue": "test"},
                  {"ParameterKey": "EnableThnAuthAdminV2", "ParameterValue": "true"}]
        payload = {"StackName": "zoolanding-auth-admin-test", "ChangeSetName": "thn-123-1",
                   "ChangeSetId": arn, "ChangeSetType": "UPDATE", "Status": "CREATE_COMPLETE",
                   "ExecutionStatus": "AVAILABLE", "Parameters": params,
                   "Changes": [{"Type": "Resource", "ResourceChange": {"Action": "Add",
                       "LogicalResourceId": PREFIX + "Function", "ResourceType": "AWS::Lambda::Function"}}]}
        self.assertEqual(self.tool.review_change_set(payload, arn, "thn-123-1", params, "enable"), "execute")
        # The AWS DescribeChangeSet response does not return ChangeSetType.
        wire_response = {k: v for k, v in payload.items() if k != "ChangeSetType"}
        self.assertEqual(self.tool.review_change_set(wire_response, arn, "thn-123-1", params, "enable"), "execute")
        for update in ({"ChangeSetId": arn + "-other"}, {"ChangeSetType": "CREATE"},
                       {"StackName": "zoolanding-auth-admin-production"}, {"Parameters": []},
                       {"NextToken": "unreviewed-page"}):
            with self.subTest(fields=list(update)), self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.review_change_set({**payload, **update}, arn, "thn-123-1", params, "enable")

    def test_resource_review_rejects_unknown_entry_type_without_provider_details(self):
        for value in (None, "private-invalid-value", {"Type": "Module"}):
            with self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.review_resources([value], "enable")

    def test_unknown_resource_type_is_never_added_even_with_the_thn_prefix(self):
        change = {"Type": "Resource", "ResourceChange": {"Action": "Add",
                  "LogicalResourceId": PREFIX + "Unexpected", "ResourceType": "Custom::UnexpectedWriter"}}
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.review_resources([change], "enable")
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.review_resources([change], "disable")

    def test_previous_lambda_version_can_be_retained_but_never_deleted_during_update(self):
        change = {"Type": "Resource", "ResourceChange": {"Action": "Remove", "PolicyAction": "Retain",
                  "LogicalResourceId": PREFIX + "FunctionVersionExample", "ResourceType": "AWS::Lambda::Version"}}
        self.tool.review_resources([change], "enable")
        change["ResourceChange"]["PolicyAction"] = "Delete"
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.review_resources([change], "enable")
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.review_resources([change], "disable")

    def test_disabling_routes_preserves_functions_roles_and_mediator_guard(self):
        from tests.test_auth_admin_v2_template_contract import _resource
        text = (ROOT / "template.yaml").read_text()
        for suffix in ("Function", "FunctionRole", "OriginAuthorizerFunction", "OriginAuthorizerFunctionRole",
                       "OwnerOperatorFunction", "OwnerOperatorFunctionRole", "OwnerOperatorAliasPolicy"):
            with self.subTest(resource=suffix):
                self.assertIn("Condition: IsThnAuthAdminV2StateProvisioned", _resource(text, PREFIX + suffix))
        for suffix in ("Api", "OwnerOperatorFunctionUrl", "OwnerOperatorPolicy"):
            self.assertIn("Condition: IsThnAuthAdminV2Enabled", _resource(text, PREFIX + suffix))
        for kind in ("AWS::Lambda::Function", "AWS::IAM::Role"):
            with self.subTest(kind=kind), self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.review_resources([{"Type": "Resource", "ResourceChange": {"Action": "Remove",
                    "LogicalResourceId": PREFIX + "Function", "ResourceType": kind}}], "disable")


class WorkflowBoundaryTests(unittest.TestCase):
    def test_dedicated_workflow_exists_and_never_uses_ordinary_parameter_or_guard_path(self):
        path = ROOT / ".github/workflows/deploy-thn-test.yml"
        self.assertTrue(path.exists(), "Dedicated THN TEST workflow is missing")
        workflow = path.read_text()
        for required in ("workflow_dispatch:", "environment: test", "refs/heads/test", "expected_source_sha",
                         "artifact-ids:", "manifest_digest", "thn_test_release.py", "operation:"):
            self.assertIn(required, workflow)
        self.assertNotIn("AUTH_ADMIN_CONFIG_JSON_BASE64", workflow)
        self.assertNotIn("check_thn_v2_ordinary_deploy.py", workflow)
        self.assertNotIn("run_test_change_set.sh", workflow)
        deploy_job = workflow.split("\n  deploy:\n", 1)[1]
        self.assertNotIn("actions/checkout", deploy_job)
        self.assertIn("zoolanding-auth-admin-test-deploy", workflow)

    def test_registration_run_has_no_credentials_and_cannot_deploy(self):
        text = (ROOT / ".github/workflows/deploy-thn-test.yml").read_text()
        self.assertIn("register:", text)
        registration = text.split("\n  register:\n", 1)[1].split("\n  validate:\n", 1)[0]
        self.assertNotIn("id-token", registration)
        self.assertNotIn("environment:", registration)
        self.assertNotIn("aws-credentials", registration)
        validation = text.split("\n  validate:\n", 1)[1].split("\n  deploy:\n", 1)[0]
        self.assertIn("if: github.event_name == 'workflow_dispatch'", validation)


if __name__ == "__main__":
    unittest.main()
