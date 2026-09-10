import unittest
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.prepare_test_parameters import ParameterPreparationError, build_parameters

class PrepareTestParametersTests(unittest.TestCase):
    def test_requires_runtime_configuration(self):
        with self.assertRaises(ParameterPreparationError):
            build_parameters({})

    def test_keeps_thn_admin_disabled(self):
        parameters, sensitive = build_parameters({"AUTH_ADMIN_CONFIG_READY": "true", "AUTH_ADMIN_CONFIG_JSON_BASE64": "e30=", "COGNITO_USER_POOL_ARNS": "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_Test"})
        self.assertEqual(parameters["EnvironmentName"], "test")
        self.assertEqual(parameters["EnableThnAuthAdminV2"], "false")
        self.assertEqual(parameters["ProvisionThnAuthAdminV2State"], "false")
        self.assertEqual(sensitive, {"AuthAdminConfigJsonBase64"})
        template = (Path(__file__).resolve().parents[1] / "template.yaml").read_text(encoding="utf-8")
        declared = set(re.findall(r"(?m)^  ([A-Za-z][A-Za-z0-9]+):$", template.split("\nMetadata:", 1)[0]))
        self.assertEqual(set(parameters), declared)

if __name__ == "__main__":
    unittest.main()
