"""Exact-source selection is public release intent, never AWS configuration."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEV_SHA = "a" * 40
DEV_TREE = "b" * 40


class ClassifyTestPromotionTests(unittest.TestCase):
    def module(self):
        path = ROOT / "tools/classify_test_promotion.py"
        self.assertTrue(path.is_file(), "exact-source classifier is not implemented")
        spec = importlib.util.spec_from_file_location("classify_test_promotion", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def selection(self, **updates):
        value = {"schemaVersion": 1, "mode": "thn-source-only", "devSha": DEV_SHA, "devTree": DEV_TREE}
        value.update(updates)
        return json.dumps(value)

    def test_absent_and_empty_preserve_legacy(self):
        module = self.module()
        for value in (None, ""):
            with self.subTest(value=value):
                self.assertEqual(module.classify_selection(value, DEV_SHA, DEV_TREE), "legacy")

    def test_exact_selection_is_source_only(self):
        self.assertEqual(self.module().classify_selection(self.selection(), DEV_SHA, DEV_TREE), "thn-source-only")

    def test_defined_invalid_selection_never_falls_through(self):
        module = self.module()
        values = [" ", "{", "null", "[]", "true", '"legacy"', self.selection(schemaVersion=True),
                  self.selection(schemaVersion=2), self.selection(mode="legacy"), self.selection(mode="unknown"),
                  self.selection(extra="field"), self.selection(devSha=42), self.selection(devTree=None),
                  self.selection(devSha="A" * 40), self.selection(devTree="b" * 39),
                  '{"schemaVersion":1,"schemaVersion":1,"mode":"thn-source-only","devSha":"' + DEV_SHA + '","devTree":"' + DEV_TREE + '"}',
                  self.selection().replace('"schemaVersion": 1', '"schemaVersion": NaN'), "{" + " " * 5000 + "}"]
        value = json.loads(self.selection())
        del value["devTree"]
        values.append(json.dumps(value))
        for value in values:
            with self.subTest(value=value[:80]):
                with self.assertRaises(module.PromotionSelectionError):
                    module.classify_selection(value, DEV_SHA, DEV_TREE)

    def test_stale_sha_or_tree_is_rejected(self):
        module = self.module()
        for value in (self.selection(devSha="c" * 40), self.selection(devTree="c" * 40)):
            with self.subTest(value=value):
                with self.assertRaises(module.PromotionSelectionError):
                    module.classify_selection(value, DEV_SHA, DEV_TREE)

    def test_invalid_current_context_is_rejected_even_without_selection(self):
        module = self.module()
        for sha, tree in ((None, DEV_TREE), (DEV_SHA, ""), ("0" * 40, DEV_TREE), (DEV_SHA, "B" * 40)):
            with self.subTest(sha=sha, tree=tree):
                with self.assertRaises(module.PromotionSelectionError):
                    module.classify_selection(None, sha, tree)

    def test_cli_reads_selection_only_from_environment_and_emits_one_mode(self):
        self.module()
        env = dict(os.environ, AUTH_TEST_PROMOTION_SELECTION_JSON=self.selection(), PROMOTED_DEV_SHA=DEV_SHA, PROMOTED_DEV_TREE=DEV_TREE)
        result = subprocess.run([sys.executable, str(ROOT / "tools/classify_test_promotion.py")], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "thn-source-only\n")
        self.assertEqual(result.stderr, "")

    def test_cli_invalid_input_is_sanitized(self):
        self.module()
        marker = "private-looking-input-must-not-be-echoed"
        env = dict(os.environ, AUTH_TEST_PROMOTION_SELECTION_JSON=marker, PROMOTED_DEV_SHA=DEV_SHA, PROMOTED_DEV_TREE=DEV_TREE)
        result = subprocess.run([sys.executable, str(ROOT / "tools/classify_test_promotion.py")], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(marker, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_rejects_argument_override(self):
        module = self.module()
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(module.main(["legacy"]), 2)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
