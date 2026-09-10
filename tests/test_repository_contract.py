import hashlib
import pathlib
import re
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


class RepositoryContractTests(unittest.TestCase):
    def test_v1_handler_source_matches_the_normalized_git_baseline(self):
        handler = (REPO_ROOT / "lambda_function.py").read_text(encoding="utf-8")
        normalized = handler.replace("\r\n", "\n")
        self.assertNotIn("lambda_handler_v2", normalized)
        v1_source = normalized.encode("utf-8")
        self.assertEqual(len(v1_source), 77_378)
        self.assertEqual(
            hashlib.sha256(v1_source).hexdigest(),
            "bef7b3b31ef6643adcbadef4dd1d7d2e7e1f82ed0dbfc3c728d910c8db2de67f",
        )

    def test_sam_template_declares_api_lambda_and_three_tables(self):
        template = (REPO_ROOT / "template.yaml").read_text(encoding="utf-8")

        self.assertIn("AWS::Serverless::HttpApi", template)
        self.assertIn("AWS::Serverless::Function", template)
        self.assertIn("AWS::DynamoDB::Table", template)
        self.assertIn("AuthAdminSessionTable", template)
        self.assertIn("AuthAdminUserStateTable", template)
        self.assertIn("AuthAdminAuditTable", template)
        self.assertIn("AUTH_ADMIN_CONFIG_JSON_BASE64", template)
        self.assertIn("CognitoUserPoolArns", template)
        self.assertNotIn("userpool/*", template)
        self.assertIn("cognito-idp:AdminAddUserToGroup", template)
        self.assertIn("cognito-idp:AdminDisableUser", template)

    def test_shared_v1_auth_admin_role_has_no_thn_v2_registry_authority(self):
        template = (REPO_ROOT / "template.yaml").read_text(encoding="utf-8")
        role_match = re.search(
            r"(?ms)^  AuthAdminFunctionRole:.*?(?=^  [A-Za-z0-9]+:|^Outputs:|\Z)",
            template,
        )

        self.assertIsNotNone(role_match)
        role = role_match.group(0)
        self.assertNotIn("ServiceBindingRegistryV2", role)
        self.assertNotIn("SERVICE_BINDING#test#thn-journal-test-v2", role)
        self.assertNotIn(
            "table/zoolanding-content-hub-test-ServiceBindingRegistryV2",
            role,
        )
        self.assertIn("Fn::Sub: ${AWS::StackName}-FunctionRole", template)

        handler = (REPO_ROOT / "lambda_function.py").read_text(encoding="utf-8")
        self.assertNotIn("service_binding_registry_consumer_v2", handler)
        self.assertTrue((REPO_ROOT / "service_binding_registry_consumer_v2.py").is_file())

    def test_workflows_enforce_dev_test_main_promotion_and_oidc_deploys(self):
        ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        deploy_test = (REPO_ROOT / ".github" / "workflows" / "deploy-test.yml").read_text(encoding="utf-8")
        deploy_prod = (REPO_ROOT / ".github" / "workflows" / "deploy-production.yml").read_text(encoding="utf-8")

        self.assertIn("Pull requests into test must come from dev.", ci)
        self.assertIn("Pull requests into main must come from test.", ci)
        self.assertIn("EVENT_NAME: ${{ github.event_name }}", ci)
        self.assertIn("BASE_REF: ${{ github.base_ref }}", ci)
        self.assertIn("HEAD_REF: ${{ github.head_ref }}", ci)
        self.assertNotIn('if [[ "${{ github.event_name }}"', ci)
        self.assertNotIn('base="${{ github.base_ref }}"', ci)
        self.assertNotIn('head="${{ github.head_ref }}"', ci)
        self.assertIn("id-token: write", deploy_test)
        self.assertIn("id-token: write", deploy_prod)
        self.assertIn("AUTH_ADMIN_CONFIG_JSON_BASE64", deploy_test)
        self.assertIn("AUTH_ADMIN_CONFIG_JSON_BASE64", deploy_prod)

        self.assertIn("prepare_test_parameters.py", deploy_test)
        self.assertIn("artifact-ids:", deploy_test)
        self.assertIn("manifest_digest", deploy_test)
        parameter_helper = (REPO_ROOT / "tools" / "prepare_test_parameters.py").read_text(encoding="utf-8")
        self.assertIn("module.load_config()", parameter_helper)
        self.assertIn("AUTH_ADMIN_ENVIRONMENT", parameter_helper)

        self.assertIn("$RUNNER_TEMP/auth-admin-config.compact.b64", deploy_prod)
        self.assertIn("auth_admin.load_config()", deploy_prod)
        self.assertNotIn('pathlib.Path("auth-admin-config.compact.b64")', deploy_prod)

    def test_ci_audits_runtime_and_owner_operator_dependencies(self):
        ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("pip-audit -r requirements.txt", ci)
        self.assertIn("pip-audit -r requirements-tools.txt", ci)

    def test_ordinary_test_deploy_cannot_disable_or_remove_thn_v2_state(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "deploy-test.yml").read_text(
            encoding="utf-8"
        )
        guard_name = "Refuse ordinary deploy when THN v2 state is active"
        credentials_position = workflow.index("aws-actions/configure-aws-credentials")
        build_position = workflow.index("Test, validate, and build exact source")
        guard_position = workflow.index(guard_name)
        deploy_position = workflow.index("Create, describe, review, and execute exact change set")

        self.assertLess(build_position, credentials_position)
        self.assertLess(build_position, guard_position)
        self.assertLess(credentials_position, guard_position)
        self.assertLess(guard_position, deploy_position)
        guard = workflow[guard_position:deploy_position]
        self.assertIn("check_thn_v2_ordinary_deploy.py", guard)
        self.assertNotIn("aws cloudformation", guard)

        parameter_helper = (REPO_ROOT / "tools" / "prepare_test_parameters.py").read_text(encoding="utf-8")
        self.assertIn('"EnableThnAuthAdminV2": "false"', parameter_helper)
        self.assertIn('"ProvisionThnAuthAdminV2State": "false"', parameter_helper)
        reviewer = (REPO_ROOT / "tools" / "review_test_change_set.py").read_text(encoding="utf-8")
        self.assertIn("stateful_resource_change_forbidden", reviewer)
        self.assertNotIn('"EnableThnAuthAdminV2=true"', workflow)
        self.assertNotIn('"ProvisionThnAuthAdminV2State=true"', workflow)
        self.assertRegex(
            workflow,
            r"(?ms)^concurrency:\s*\n\s+group: zoolanding-auth-admin-test-deploy\s*\n\s+cancel-in-progress: false\s*$",
        )

    def test_readme_documents_cookie_csrf_and_no_browser_tokens(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("__Host-zlp_session", readme)
        self.assertIn("zlp_csrf", readme)
        self.assertIn("HttpOnly", readme)
        self.assertIn("No JWT, ID token, access token, or refresh token is returned to the browser", readme)
        self.assertIn("/mi-cuenta", readme)
        self.assertIn("/admin/*", readme)


if __name__ == "__main__":
    unittest.main()
