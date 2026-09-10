import pathlib
import tempfile
import unittest
from unittest import mock

from tools import build_lambda_artifact as builder
from tools import check_lambda_artifacts as checker


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


class LambdaArtifactBuildContractTests(unittest.TestCase):
    def test_template_uses_makefile_builds_and_direct_v2_handler(self):
        template = (REPO_ROOT / "template.yaml").read_text(encoding="utf-8")

        self.assertEqual(template.count("BuildMethod: makefile"), 4)
        self.assertIn("Handler: lambda_function.lambda_handler", template)
        self.assertIn("Handler: auth_admin_session_v2.lambda_handler", template)
        self.assertIn("Handler: auth_admin_origin_authorizer_v2.lambda_handler", template)
        self.assertIn("Handler: auth_admin_owner_operator_v2.lambda_handler", template)
        self.assertNotIn("lambda_function.lambda_handler_v2", template)

    def test_builder_copies_only_each_functions_runtime_source_allowlist(self):
        expected = {
            "AuthAdminFunction": {"lambda_function.py"},
            "ThnAuthAdminV2Function": {
                "auth_admin_qa_state_v2.py",
                "auth_admin_current_user_v2.py",
                "auth_admin_session_v2.py",
                "service_binding_registry_consumer_v2.py",
            },
            "ThnAuthAdminV2OriginAuthorizerFunction": {
                "auth_admin_origin_authorizer_v2.py",
            },
            "ThnAuthAdminV2OwnerOperatorFunction": {
                "auth_admin_qa_state_v2.py",
                "auth_admin_qa_operator_v2.py",
                "auth_admin_current_user_v2.py",
                "auth_admin_owner_operator_v2.py",
                "tools/provision_thn_owner.py",
                "tools/provision_thn_qa.py",
            },
        }

        for target, names in expected.items():
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                destination = pathlib.Path(directory)
                builder.build_artifact(target, destination, install_dependencies=False)
                self.assertEqual(
                    {
                        path.relative_to(destination).as_posix()
                        for path in destination.rglob("*")
                        if path.is_file()
                    },
                    names,
                )
                checker.validate_artifact(target, destination)

    def test_builder_and_checker_fail_closed_for_unknown_target_or_extra_project_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory)
            with self.assertRaises(builder.ArtifactBuildError):
                builder.build_artifact("UnknownFunction", destination, install_dependencies=False)

        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory)
            builder.build_artifact(
                "ThnAuthAdminV2Function",
                destination,
                install_dependencies=False,
            )
            (destination / "provision_thn_owner.py").write_text("forbidden", encoding="utf-8")
            with self.assertRaises(checker.ArtifactValidationError):
                checker.validate_artifact("ThnAuthAdminV2Function", destination)

    def test_artifacts_with_external_runtime_dependencies_install_their_requirements(self):
        expected_requirements = {
            "AuthAdminFunction": "requirements.txt",
            "ThnAuthAdminV2Function": "requirements.txt",
            "ThnAuthAdminV2OwnerOperatorFunction": "requirements-tools.txt",
        }
        for target, requirements_name in expected_requirements.items():
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory, mock.patch.object(
                builder.subprocess,
                "run",
            ) as run:
                destination = pathlib.Path(directory)

                builder.build_artifact(target, destination)

                run.assert_called_once()
                command = run.call_args.args[0]
                self.assertIn(str(REPO_ROOT / requirements_name), command)
                # Lambda uses Linux x86_64 CPython 3.13, even on a Windows builder.
                self.assertEqual(command[command.index("--platform") + 1], "manylinux2014_x86_64")
                self.assertEqual(command[command.index("--implementation") + 1], "cp")
                self.assertEqual(command[command.index("--python-version") + 1], "3.13")
                self.assertIn("--only-binary=:all:", command)
                self.assertEqual(command[-2:], ["--target", str(destination.resolve())])
                self.assertTrue(run.call_args.kwargs["check"])

    def test_host_generated_cffi_console_launchers_are_not_shipped(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory)

            def install(*args, **kwargs):
                scripts = destination / "bin"
                scripts.mkdir()
                for name in ("cffi-gen-src.exe", "cffi-gen-src", "retained.txt"):
                    (scripts / name).write_text("generated", encoding="utf-8")

            with mock.patch.object(builder.subprocess, "run", side_effect=install):
                builder.build_artifact("ThnAuthAdminV2Function", destination)
            self.assertFalse((destination / "bin/cffi-gen-src.exe").exists())
            self.assertFalse((destination / "bin/cffi-gen-src").exists())
            self.assertTrue((destination / "bin/retained.txt").is_file())

    def test_checker_rejects_foreign_native_libraries_and_launchers(self):
        for name in ("bin/tool.exe", "cryptography/library.dll", "_cffi_backend.pyd"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                destination = pathlib.Path(directory)
                builder.build_artifact("ThnAuthAdminV2Function", destination, install_dependencies=False)
                extra = destination / name
                extra.parent.mkdir(parents=True, exist_ok=True)
                extra.write_text("foreign binary", encoding="utf-8")
                with self.assertRaises(checker.ArtifactValidationError):
                    checker.validate_artifact("ThnAuthAdminV2Function", destination)


if __name__ == "__main__":
    unittest.main()
