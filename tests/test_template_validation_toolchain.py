"""The TEST release must use the schema validator proven by candidate QA."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TemplateValidationToolchainTests(unittest.TestCase):
    def test_test_release_validates_current_schemas_without_credentials(self):
        workflow = (ROOT / ".github/workflows/deploy-test.yml").read_text(encoding="utf-8")
        match = re.search(r"(?ms)^  validate:\n(.*?)(?=^  [a-z][a-z-]+:|\Z)", workflow)
        self.assertIsNotNone(match)
        script = match.group(1)
        self.assertIn("    permissions:\n      contents: read\n", script)
        self.assertNotIn("id-token:", script)
        self.assertNotRegex(script, r"(?m)^    environment:")
        self.assertIn('python -m venv "$RUNNER_TEMP/thn-cfn-lint"', script)
        self.assertIn("cfn-lint==1.56.0", script)
        command = '"$RUNNER_TEMP/thn-cfn-lint/bin/cfn-lint" -t template.yaml -r us-east-1'
        self.assertIn(command, script)
        self.assertLess(script.index(command), script.index("sam build --no-cached"))
        for bypass in ("--ignore-checks", "--non-zero-exit-code", "|| true"):
            self.assertNotIn(bypass, script)
        self.assertNotIn("sam validate", script)


if __name__ == "__main__":
    unittest.main()
