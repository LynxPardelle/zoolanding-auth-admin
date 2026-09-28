from pathlib import Path
import json
import tempfile
import unittest
from unittest import mock
import yaml
from tools import build_lambda_artifact as builder
from tools import check_lambda_artifacts as checker
from tools.prepare_thn_production_template import prepare_template

ROOT = Path(__file__).resolve().parents[1]

class EnvironmentArtifactInventoryTests(unittest.TestCase):
    def test_maps_equal_actual_native_function_targets(self):
        source = yaml.safe_load((ROOT / 'template.yaml').read_text())
        for environment, template in [('test', source), ('production', prepare_template(source))]:
            actual = {name for name, resource in template['Resources'].items()
                      if resource['Type'] == 'AWS::Serverless::Function'}
            selected = builder.source_allowlist_for_environment(environment)
            self.assertEqual(set(selected), actual)
            self.assertEqual(len(selected), 4)
        self.assertNotIn('ThnProductionOwnerOperatorV2Function', builder.TEST_SOURCE_ALLOWLIST)
        self.assertNotIn('ThnAuthAdminV2OwnerOperatorFunction', builder.PRODUCTION_SOURCE_ALLOWLIST)
        with self.assertRaises(builder.ArtifactBuildError):
            builder.source_allowlist_for_environment('prod')

    def test_real_builder_and_checker_reject_cross_environment_extra_and_missing_targets(self):
        source = yaml.safe_load((ROOT / 'template.yaml').read_text())
        for environment, template in [('test', source), ('production', prepare_template(source))]:
            with self.subTest(environment=environment), tempfile.TemporaryDirectory() as temporary:
                build = Path(temporary)
                (build / 'template.yaml').write_text(json.dumps(template))
                selected = builder.source_allowlist_for_environment(environment)
                for target in selected:
                    builder.build_artifact(target, build / target, install_dependencies=False)
                checker.validate_inventory(build, environment)
                other = 'production' if environment == 'test' else 'test'
                with self.assertRaises(checker.ArtifactValidationError):
                    checker.validate_inventory(build, other)
                (build / 'UnexpectedFunction').mkdir()
                with self.assertRaises(checker.ArtifactValidationError):
                    checker.validate_inventory(build, environment)
                (build / 'UnexpectedFunction').rmdir()
                target = next(iter(selected))
                (build / target).rename(build / 'MissingTarget')
                with self.assertRaises(checker.ArtifactValidationError):
                    checker.validate_inventory(build, environment)

    def test_default_cli_checks_real_test_four_and_explicit_production_checks_other_four(self):
        source = yaml.safe_load((ROOT / 'template.yaml').read_text())
        for environment, template in [('test', source), ('production', prepare_template(source))]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                build = root / '.aws-sam' / 'build'
                build.mkdir(parents=True)
                (build / 'template.yaml').write_text(json.dumps(template))
                actual = {name for name, value in template['Resources'].items()
                          if value['Type'] == 'AWS::Serverless::Function'}
                for target in actual:
                    builder.build_artifact(target, build / target, install_dependencies=False)
                with mock.patch.object(checker, 'REPOSITORY_ROOT', root):
                    args = [] if environment == 'test' else ['--environment', 'production']
                    self.assertEqual(checker.main(args), 0)
