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


if __name__ == "__main__":
    unittest.main()
