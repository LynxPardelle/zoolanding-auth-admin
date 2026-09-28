import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STACK_NAME = "zoolanding-auth-admin-test"


class TestDeliveryWorkflowContractTests(unittest.TestCase):
    def workflow(self, name: str) -> str:
        path = ROOT / ".github" / "workflows" / name
        self.assertTrue(path.is_file(), f"missing {path}")
        return path.read_text(encoding="utf-8")

    def assert_actions_are_commit_pinned(self, workflow: str) -> None:
        for value in re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", workflow):
            if value.startswith("./"):
                continue
            self.assertRegex(value, r"@[a-f0-9]{40}$")

    def assert_release_boundary(self, workflow: str) -> None:
        for value in (
            "environment: test",
            "id-token: write",
            "artifact-ids:",
            "manifest_digest",
            "sha256sum",
            "recomputed-build-manifest.sha256",
            "cmp --silent",
            "create-change-set",
            "describe-change-set",
            "execute-change-set",
            "stateful_resource_change_forbidden",
            "Post-deploy smoke",
            STACK_NAME,
        ):
            self.assertIn(value, workflow)
        self.assertNotIn("sam deploy", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assert_actions_are_commit_pinned(workflow)

    def test_deploy_uses_exact_test_artifact_and_reviewed_change_set(self):
        workflow = self.workflow("deploy-test.yml")
        self.assertIn("branches: [test]", workflow)
        self.assertIn("${{ github.sha }}", workflow)
        self.assertRegex(workflow, r"\^\[a-f0-9\]\{40\}\$")
        self.assert_release_boundary(workflow)

    def test_rollback_selects_one_recorded_immutable_release(self):
        workflow = self.workflow("rollback-test.yml")
        for value in (
            "workflow_dispatch:",
            "source_run_id:",
            "source_artifact_id:",
            "source_sha:",
            "source_manifest_sha256:",
            "run-id:",
            "refs/heads/test",
            "getWorkflowRun",
        ):
            self.assertIn(value, workflow)
        self.assert_release_boundary(workflow)

    def job(self, name: str) -> str:
        workflow = self.workflow("deploy-test.yml")
        match = re.search(r"(?ms)^  " + re.escape(name) + r":\n.*?(?=^  [A-Za-z0-9_-]+:|\Z)", workflow)
        self.assertIsNotNone(match, f"missing job {name}")
        return match.group(0)

    def test_only_explicit_validated_legacy_mode_can_start_privileged_job(self):
        deploy = self.job("deploy")
        self.assertIn("if: needs.validate.outputs.promotion_mode == 'legacy'", deploy)
        self.assertNotIn("vars.AUTH_TEST_PROMOTION_SELECTION_JSON", deploy)
        self.assertNotIn("!= 'thn-source-only'", deploy)

    def test_selector_is_read_once_in_credential_free_job_before_build(self):
        workflow = self.workflow("deploy-test.yml")
        self.assertEqual(workflow.count("vars.AUTH_TEST_PROMOTION_SELECTION_JSON"), 1)
        validate = self.job("validate")
        self.assertIn("promotion_mode: ${{ steps.promotion.outputs.mode }}", validate)
        self.assertLess(validate.index("Verify exact TEST promotion context"), validate.index("tools/classify_test_promotion.py"))
        self.assertLess(validate.index("tools/classify_test_promotion.py"), validate.index("Test, validate, and build exact source"))
        for value in ("environment:", "id-token:", "secrets.", "configure-aws-credentials", "sam package", "execute-change-set"):
            self.assertNotIn(value, validate)

    def test_thn_transport_verifier_is_independent_and_unprivileged(self):
        verify = self.job("verify-thn-validation")
        self.assertIn("if: needs.validate.outputs.promotion_mode == 'thn-source-only'", verify)
        for value in ("contents: read", "artifact-ids:", "ref: ${{ github.sha }}", "tools/test_validation_artifact.py verify", "EXPECTED_MANIFEST_SHA256", "needs.validate.outputs.dev_sha", "needs.validate.outputs.dev_tree"):
            self.assertIn(value, verify)
        for value in ("environment:", "id-token:", "secrets.", "vars.", "configure-aws-credentials", "sam package", "execute-change-set"):
            self.assertNotIn(value, verify)

    def test_thn_and_legacy_artifacts_have_separate_producers(self):
        validate = self.job("validate")
        self.assertIn("zoolanding-auth-admin-test-validation-", validate)
        self.assertIn("tools/test_validation_artifact.py create", validate)
        legacy = validate[validate.index("- name: Assemble immutable release artifact"):validate.index("- name: Compute release identity")]
        self.assertIn("if: steps.promotion.outputs.mode == 'legacy'", legacy)
        self.assertIn("zoolanding-test-release/v1", legacy)

    def test_invalid_classifier_output_cannot_be_emitted(self):
        validate = self.job("validate")
        self.assertIn("legacy|thn-source-only)", validate)
        self.assertIn("promotion_mode_invalid", validate)
        self.assertIn("set -euo pipefail", validate)


if __name__ == "__main__":
    unittest.main()
