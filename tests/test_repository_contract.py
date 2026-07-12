import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


class RepositoryContractTests(unittest.TestCase):
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

        for workflow_name in ("deploy-dev.yml", "deploy-test.yml", "deploy-production.yml"):
            workflow = (REPO_ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
            self.assertIn("$RUNNER_TEMP/auth-admin-config.compact.b64", workflow)
            self.assertIn("auth_admin.load_config()", workflow)
            self.assertNotIn('pathlib.Path("auth-admin-config.compact.b64")', workflow)

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
