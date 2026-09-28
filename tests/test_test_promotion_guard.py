"""Run the workflow's unchanged Bash promotion guard against real local Git DAGs."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TestPromotionGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.env = dict(os.environ, GIT_AUTHOR_NAME="Release Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                        GIT_COMMITTER_NAME="Release Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")
        self.git("remote", "add", "origin", self.repo.as_posix())
        self.base_tree = self.tree("base")
        self.dev_tree = self.tree("reviewed source")
        self.base = self.commit(self.base_tree)
        self.dev = self.commit(self.dev_tree, self.base)
        self.other = self.commit(self.base_tree, self.base)
        self.git("update-ref", "refs/heads/dev", self.dev)
        self.valid = self.commit(self.dev_tree, self.base, self.dev)
        workflow = (ROOT / ".github/workflows/deploy-test.yml").read_text()
        guard = workflow.split("- name: Verify exact TEST promotion context\n", 1)[1].split("\n      - ", 1)[0]
        body = guard.split("        run: |\n", 1)[1]
        self.guard = "\n".join(line[10:] for line in body.splitlines())
        self.bash = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash")
        self.assertTrue(self.bash and Path(self.bash).is_file(), "Bash is required to test the actual release guard")

    def git(self, *args, input=None):
        result = subprocess.run(["git", *args], cwd=self.repo, env=self.env, input=input, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def tree(self, text):
        blob = self.git("hash-object", "-w", "--stdin", input=text)
        return self.git("mktree", input=f"100644 blob {blob}\tfixture.txt\n")

    def commit(self, tree, *parents):
        return self.git("commit-tree", tree, *[part for parent in parents for part in ("-p", parent)], input="fixture\n")

    def run_guard(self, commit, **updates):
        self.git("update-ref", "refs/heads/candidate", commit)
        self.git("symbolic-ref", "HEAD", "refs/heads/candidate")
        env = dict(self.env, RELEASE_SHA=commit, BEFORE_SHA=self.base, PUSH_FORCED="false", GITHUB_REF="refs/heads/test")
        env.update(updates)
        return subprocess.run([self.bash, "--noprofile", "--norc", "-c", self.guard], cwd=self.repo, env=env, capture_output=True, text=True)

    def test_exact_two_parent_promotion_passes(self):
        result = self.run_guard(self.valid)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_direct_squash_wrong_parents_octopus_and_tree_drift_fail(self):
        candidates = [self.dev, self.commit(self.dev_tree, self.base),
                      self.commit(self.dev_tree, self.other, self.dev),
                      self.commit(self.dev_tree, self.base, self.other),
                      self.commit(self.dev_tree, self.base, self.dev, self.other),
                      self.commit(self.base_tree, self.base, self.dev)]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.assertNotEqual(self.run_guard(candidate).returncode, 0)

    def test_stale_dev_ref_fails(self):
        self.git("update-ref", "refs/heads/dev", self.commit(self.dev_tree, self.dev))
        self.assertNotEqual(self.run_guard(self.valid).returncode, 0)

    def test_forced_wrong_ref_bad_before_and_invalid_source_fail(self):
        for updates in ({"PUSH_FORCED": "true"}, {"GITHUB_REF": "refs/heads/main"}, {"BEFORE_SHA": self.other}, {"RELEASE_SHA": "bad"}):
            with self.subTest(updates=updates):
                self.assertNotEqual(self.run_guard(self.valid, **updates).returncode, 0)


if __name__ == "__main__":
    unittest.main()
