"""Exercise the real validation-only artifact, not an artifact-owned verifier."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from tools.build_lambda_artifact import SOURCE_ALLOWLIST


ROOT = Path(__file__).resolve().parents[1]
CONTEXT = {"source_sha": "a" * 40, "dev_sha": "b" * 40, "dev_tree": "c" * 40,
           "run_id": "123", "run_attempt": "2"}


class TestValidationArtifactTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "tools/test_validation_artifact.py"
        self.assertTrue(path.is_file(), "validation-only artifact tool is not implemented")
        spec = importlib.util.spec_from_file_location("test_validation_artifact", path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.build = self.parent / "build"
        self.build.mkdir()
        (self.build / "template.yaml").write_text("Resources: {}\n", encoding="utf-8")
        for target, names in SOURCE_ALLOWLIST.items():
            for name in names:
                path = self.build / target / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
        self.manifest = self.parent / "validation-manifest.json"

    def create(self, context=None):
        return self.module.create_artifact(self.build, self.manifest, context or CONTEXT)

    def verify(self, digest, context=None):
        return self.module.verify_artifact(self.build, self.manifest, digest, context or CONTEXT)

    def test_create_and_verify_complete_four_target_inventory(self):
        digest = self.create()
        self.assertRegex(digest, r"^[a-f0-9]{64}$")
        self.assertEqual(digest, hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        self.verify(digest)
        metadata = json.loads((self.build / "validation-metadata.json").read_text())
        self.assertEqual(metadata["schema"], "zoolanding-test-validation/v1")
        self.assertIs(metadata["deployable"], False)
        self.assertEqual(metadata["promotion_mode"], "thn-source-only")
        self.assertEqual(metadata["purpose"], "validation-only")
        self.assertTrue(CONTEXT.items() <= metadata.items())
        manifest = json.loads(self.manifest.read_text())
        self.assertEqual(set(manifest["files"]), {p.relative_to(self.build).as_posix() for p in self.build.rglob("*") if p.is_file()})
        self.assertFalse((self.build / "release-metadata.json").exists())
        self.assertFalse((self.build / "release-tools").exists())

    def test_transport_rejects_added_removed_and_changed_file(self):
        digest = self.create()
        target = self.build / "AuthAdminFunction/lambda_function.py"
        original = target.read_bytes()
        for operation in ("change", "remove", "add"):
            with self.subTest(operation=operation):
                if operation == "change":
                    target.write_bytes(b"changed")
                elif operation == "remove":
                    target.unlink()
                else:
                    (self.build / "AuthAdminFunction/extra.py").write_text("unexpected")
                with self.assertRaises(self.module.ValidationArtifactError):
                    self.verify(digest)
                target.write_bytes(original)

    def test_each_provenance_coordinate_must_match(self):
        digest = self.create()
        for key in CONTEXT:
            expected = dict(CONTEXT, **{key: "d" * 40 if key.endswith(("sha", "tree")) else "3"})
            with self.subTest(key=key), self.assertRaises(self.module.ValidationArtifactError):
                self.verify(digest, expected)

    def test_invalid_context_is_rejected_before_writing(self):
        for updates in ({"run_id": "0"}, {"run_attempt": 1}, {"source_sha": "A" * 40}, {"dev_tree": "0" * 40}, {"extra": "unknown"}):
            with self.subTest(updates=updates), self.assertRaises(self.module.ValidationArtifactError):
                self.create(dict(CONTEXT, **updates))
        self.assertFalse(self.manifest.exists())
        self.assertFalse((self.build / "validation-metadata.json").exists())

    def test_wrong_or_missing_external_digest_is_rejected(self):
        self.create()
        for digest in (None, "", "0" * 64, "A" * 64):
            with self.subTest(digest=digest), self.assertRaises(self.module.ValidationArtifactError):
                self.verify(digest)

    def test_creation_rejects_unexpected_roots_foreign_binaries_and_source_mismatch(self):
        for relative in ("release-metadata.json", "release-tools/runner.py", "AuthAdminFunction/payload.exe", "AuthAdminFunction/tools/steal.py"):
            path = self.build / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("not an allowed artifact")
            with self.subTest(relative=relative), self.assertRaises(self.module.ValidationArtifactError):
                self.create()
            path.unlink()
            if relative.startswith("release-tools/"):
                path.parent.rmdir()
        (self.build / "AuthAdminFunction/lambda_function.py").write_text("altered source")
        with self.assertRaises(self.module.ValidationArtifactError):
            self.create()

    def test_creation_does_not_overwrite_existing_metadata_or_manifest(self):
        digest = self.create()
        with self.assertRaises(self.module.ValidationArtifactError):
            self.create()
        self.assertEqual(hashlib.sha256(self.manifest.read_bytes()).hexdigest(), digest)

    def test_closed_metadata_rejects_deployable_legacy_unknown_and_wrong_types(self):
        self.create()
        path = self.build / "validation-metadata.json"
        original = json.loads(path.read_text())
        for updates in ({"schema": "zoolanding-test-release/v1"}, {"deployable": True}, {"deployable": 0}, {"purpose": "deploy"}, {"promotion_mode": "legacy"}, {"unknown": "value"}):
            path.write_text(json.dumps(dict(original, **updates)))
            manifest = json.loads(self.manifest.read_text())
            manifest["files"]["validation-metadata.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
            self.manifest.write_text(json.dumps(manifest))
            with self.subTest(updates=updates), self.assertRaises(self.module.ValidationArtifactError):
                self.verify(hashlib.sha256(self.manifest.read_bytes()).hexdigest())

    def test_manifest_schema_duplicate_unknown_and_oversize_rejected(self):
        self.create()
        original = self.manifest.read_text()
        values = ["{}", "[]", original[:-1] + ',"files":{}}', original[:-1] + ',"extra":1}', " " * 2_100_000]
        for value in values:
            self.manifest.write_text(value)
            with self.subTest(length=len(value)), self.assertRaises(self.module.ValidationArtifactError):
                self.verify(hashlib.sha256(self.manifest.read_bytes()).hexdigest())

    def test_actual_legacy_deploy_and_rollback_metadata_consumers_reject_validation_schema(self):
        self.create()
        metadata = (self.build / "validation-metadata.json").read_bytes()
        legacy_root = self.parent / ".aws-sam/build"
        legacy_root.mkdir(parents=True)
        (legacy_root / "release-metadata.json").write_bytes(metadata)
        for filename, args in (("deploy-test.yml", [CONTEXT["source_sha"], "zoolanding-auth-admin"]),
                               ("rollback-test.yml", [CONTEXT["run_id"], CONTEXT["source_sha"], "zoolanding-auth-admin"])):
            workflow = (ROOT / ".github/workflows" / filename).read_text()
            candidates = re.findall(r"<<'PY'\n(.*?)\n          PY", workflow, re.S)
            code = next(value for value in candidates if "release_metadata_invalid" in value)
            code = "\n".join(line[10:] for line in code.splitlines())
            result = subprocess.run([sys.executable, "-", *args], input=code, cwd=self.parent, capture_output=True, text=True)
            with self.subTest(filename=filename):
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr.strip(), "release_metadata_invalid")
                self.assertLess(workflow.index("release_metadata_invalid"), workflow.index("configure-aws-credentials"))

    def test_cli_failure_does_not_echo_paths_or_input(self):
        marker = "private-looking-path-never-output"
        result = subprocess.run([sys.executable, str(ROOT / "tools/test_validation_artifact.py"), "verify", marker, marker], env=dict(os.environ, EXPECTED_SOURCE_SHA=marker), capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(marker, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_real_cli_round_trip_after_transport_and_attempt_replay_rejection(self):
        env = dict(os.environ, **{"EXPECTED_" + key.upper(): value for key, value in CONTEXT.items()})
        command = [sys.executable, "-S", str(ROOT / "tools/test_validation_artifact.py")]
        created = subprocess.run([*command, "create", str(self.build), str(self.manifest)], env=env, capture_output=True, text=True)
        self.assertEqual(created.returncode, 0, created.stderr)
        env["EXPECTED_MANIFEST_SHA256"] = created.stdout.strip()
        with tempfile.TemporaryDirectory() as destination:
            transported = Path(destination)
            shutil.copytree(self.build, transported / "build")
            shutil.copyfile(self.manifest, transported / self.manifest.name)
            args = [*command, "verify", str(transported / "build"), str(transported / self.manifest.name)]
            verified = subprocess.run(args, env=env, capture_output=True, text=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(verified.stdout, "validation_artifact_verified\n")
            env["EXPECTED_RUN_ATTEMPT"] = "3"
            replay = subprocess.run(args, env=env, capture_output=True, text=True)
            self.assertEqual(replay.returncode, 2)
            self.assertEqual(replay.stderr, "validation_artifact_invalid\n")

    def test_extra_transport_payload_is_rejected(self):
        digest = self.create()
        (self.parent / "extra.py").write_text("not part of this transport")
        with self.assertRaises(self.module.ValidationArtifactError):
            self.verify(digest)

    def test_source_drift_is_rejected_even_with_recomputed_manifest_and_digest(self):
        self.create()
        source = self.build / "AuthAdminFunction/lambda_function.py"
        source.write_text("changed but rehashed")
        manifest = json.loads(self.manifest.read_text())
        manifest["files"]["AuthAdminFunction/lambda_function.py"] = hashlib.sha256(source.read_bytes()).hexdigest()
        self.manifest.write_text(json.dumps(manifest))
        with self.assertRaises(self.module.ValidationArtifactError):
            self.verify(hashlib.sha256(self.manifest.read_bytes()).hexdigest())

    def test_template_must_be_a_regular_file_not_an_empty_directory(self):
        template = self.build / "template.yaml"
        template.unlink()
        template.mkdir()
        with self.assertRaises(self.module.ValidationArtifactError):
            self.create()

    def test_linked_payload_is_rejected(self):
        target = self.build / "AuthAdminFunction/linked.py"
        try:
            target.symlink_to(self.build / "AuthAdminFunction/lambda_function.py")
        except OSError as error:
            if os.name == "nt" and getattr(error, "winerror", None) == 1314:
                # A junction exercises the Windows reparse-point boundary without
                # requesting symlink privilege; Linux uses an actual file link.
                target = self.build / "AuthAdminFunction/linked-directory"
                command = "New-Item -ItemType Junction -Path '{}' -Target '{}' | Out-Null".format(
                    str(target).replace("'", "''"), str(self.build / "ThnAuthAdminV2Function").replace("'", "''"))
                result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            else:
                raise
        with self.assertRaises(self.module.ValidationArtifactError):
            self.create()


if __name__ == "__main__":
    unittest.main()
