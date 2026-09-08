"""Offline contracts for the dedicated THN parameter path, never ordinary deploy."""

import base64
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from tools import prepare_test_parameters as ordinary


ROOT = Path(__file__).resolve().parents[1]


def selection():
    return {
        "schemaVersion": 1,
        "environment": "test",
        "parameters": {
            "EnableThnAuthAdminV2": "true",
            "ProvisionThnAuthAdminV2State": "true",
            "ThnAuthAdminV2TerminationProtectionGate": "CONFIRMED_ENABLED",
            "ThnAuthAdminV2DescriptorVersionId": "descriptor-test-1",
            "ThnAuthAdminV2DescriptorSha256": "a" * 64,
            "ThnAuthAdminV2AuthPolicyVersion": "policy-test-1",
            "ThnAuthAdminV2OriginHeaderSha256Current": "b" * 64,
            "ThnAuthAdminV2OriginHeaderSha256Previous": "0" * 64,
        },
    }


def environment(payload=None):
    return {
        "AUTH_ADMIN_CONFIG_READY": "true",
        "AUTH_ADMIN_CONFIG_JSON_BASE64": base64.b64encode(b'{"version":1,"profiles":[]}').decode(),
        "COGNITO_USER_POOL_ARNS": "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_Test",
        "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/example-test-release",
        "AWS_REGION": "us-east-1",
        "THN_V2_TEST_PARAMETERS_JSON": json.dumps(selection() if payload is None else payload),
    }


class DedicatedParameterTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "tools/prepare_thn_test_parameters.py"
        self.assertTrue(path.is_file(), "Dedicated THN release preparation is missing")
        spec = importlib.util.spec_from_file_location("thn_release_parameters", path)
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)

    def test_complete_selection_changes_only_eight_thn_parameters(self):
        values, sensitive = self.tool.build_parameters(environment())
        before, _ = ordinary.build_parameters(environment())
        self.assertEqual({k: v for k, v in values.items() if k not in selection()["parameters"]},
                         {k: v for k, v in before.items() if k not in selection()["parameters"]})
        self.assertEqual({k: values[k] for k in selection()["parameters"]}, selection()["parameters"])
        self.assertEqual(sensitive, {"AuthAdminConfigJsonBase64",
                                    "ThnAuthAdminV2OriginHeaderSha256Current",
                                    "ThnAuthAdminV2OriginHeaderSha256Previous"})

    def test_ordinary_path_stays_disabled_even_when_selection_is_present(self):
        values, _ = ordinary.build_parameters(environment())
        self.assertEqual(values["EnableThnAuthAdminV2"], "false")
        self.assertEqual(values["ProvisionThnAuthAdminV2State"], "false")

    def test_requires_explicit_selection(self):
        for raw in (None, "", " ", "[]", "null", "{" , "x" * 16385):
            with self.subTest(raw_type=type(raw).__name__):
                env = environment()
                if raw is None:
                    del env["THN_V2_TEST_PARAMETERS_JSON"]
                else:
                    env["THN_V2_TEST_PARAMETERS_JSON"] = raw
                with self.assertRaises(ordinary.ParameterPreparationError):
                    self.tool.build_parameters(env)

    def test_rejects_unknown_duplicate_missing_and_wrong_typed_fields(self):
        cases = []
        for field in selection()["parameters"]:
            value = selection()
            del value["parameters"][field]
            cases.append(value)
        for change in ({"environment": "prod"}, {"schemaVersion": True},
                       {"domain": "unrelated.example"}, {"parameters": []}):
            cases.append({**selection(), **change})
        value = selection()
        value["parameters"]["EnvironmentName"] = "prod"
        cases.append(value)
        for payload in cases:
            with self.subTest(fields=list(payload)):
                with self.assertRaises(ordinary.ParameterPreparationError):
                    self.tool.build_parameters(environment(payload))
        env = environment()
        env["THN_V2_TEST_PARAMETERS_JSON"] = env["THN_V2_TEST_PARAMETERS_JSON"].replace(
            '"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1')
        with self.assertRaises(ordinary.ParameterPreparationError):
            self.tool.build_parameters(env)

    def test_enabled_runtime_requires_retained_state_descriptor_and_origin_proof(self):
        mutations = {
            "EnableThnAuthAdminV2": [True, "yes", "TRUE"],
            "ProvisionThnAuthAdminV2State": ["false", False],
            "ThnAuthAdminV2TerminationProtectionGate": ["BLOCKED", "confirmed_enabled"],
            "ThnAuthAdminV2DescriptorVersionId": ["BLOCKED", "", "../unsafe", "a\nb"],
            "ThnAuthAdminV2DescriptorSha256": ["0" * 64, "A" * 64, "a" * 63],
            "ThnAuthAdminV2AuthPolicyVersion": ["BLOCKED", "", "a" * 129],
            "ThnAuthAdminV2OriginHeaderSha256Current": ["0" * 64, "b" * 63],
            "ThnAuthAdminV2OriginHeaderSha256Previous": ["b" * 64, "g" * 64],
        }
        for field, invalid_values in mutations.items():
            for invalid in invalid_values:
                with self.subTest(field=field):
                    value = selection()
                    value["parameters"][field] = invalid
                    with self.assertRaises(ordinary.ParameterPreparationError):
                        self.tool.build_parameters(environment(value))

    def test_state_only_provisioning_does_not_enable_runtime(self):
        value = selection()
        value["parameters"]["EnableThnAuthAdminV2"] = "false"
        values, _ = self.tool.build_parameters(environment(value))
        self.assertEqual(values["EnableThnAuthAdminV2"], "false")
        self.assertEqual(values["ProvisionThnAuthAdminV2State"], "true")

    def test_limits_region_and_role_to_test_deployment_inputs(self):
        for change in ({"AWS_REGION": "eu-west-1"}, {"AWS_DEFAULT_REGION": "eu-west-1"},
                       {"AWS_ROLE_ARN": "arn:aws:iam::123456789012:user/operator"},
                       {"AWS_ROLE_ARN": ""}):
            with self.subTest(keys=list(change)):
                with self.assertRaises(ordinary.ParameterPreparationError):
                    self.tool.build_parameters({**environment(), **change})

    def test_masks_origin_proof_digests_in_review_material(self):
        values, sensitive = self.tool.build_parameters(environment())
        with tempfile.TemporaryDirectory() as temp:
            ordinary.write_parameter_files(Path(temp), values, sensitive)
            expected = (Path(temp) / "expected-parameters.txt").read_text()
            required = (Path(temp) / "required-parameters.txt").read_text()
            self.assertNotIn("b" * 64, expected)
            self.assertNotIn("0" * 64, expected)
            self.assertIn("ThnAuthAdminV2OriginHeaderSha256Current\n", required)
            self.assertIn("ThnAuthAdminV2OriginHeaderSha256Previous\n", required)

    def test_error_never_contains_selection_values(self):
        env = environment()
        value = deepcopy(selection())
        value["parameters"]["unexpected"] = "private-input-must-not-be-echoed"
        env["THN_V2_TEST_PARAMETERS_JSON"] = json.dumps(value)
        with self.assertRaises(ordinary.ParameterPreparationError) as raised:
            self.tool.build_parameters(env)
        self.assertEqual(str(raised.exception), "thn_test_selection_invalid")


if __name__ == "__main__":
    unittest.main()
