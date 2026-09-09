#!/usr/bin/env python3
"""Build exact allowlisted Auth Admin Lambda artifacts for SAM makefile builds."""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
from collections.abc import Sequence


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_ALLOWLIST = {
    "AuthAdminFunction": ("lambda_function.py",),
    "ThnAuthAdminV2Function": (
        "auth_admin_qa_state_v2.py",
        "auth_admin_current_user_v2.py",
        "auth_admin_session_v2.py",
        "service_binding_registry_consumer_v2.py",
    ),
    "ThnAuthAdminV2OriginAuthorizerFunction": (
        "auth_admin_origin_authorizer_v2.py",
    ),
    "ThnAuthAdminV2OwnerOperatorFunction": (
        "auth_admin_qa_state_v2.py",
        "auth_admin_qa_operator_v2.py",
        "auth_admin_current_user_v2.py",
        "auth_admin_owner_operator_v2.py",
        "tools/provision_thn_owner.py",
        "tools/provision_thn_qa.py",
    ),
}
RUNTIME_REQUIREMENTS = {
    "AuthAdminFunction": "requirements.txt",
    "ThnAuthAdminV2Function": "requirements.txt",
    "ThnAuthAdminV2OriginAuthorizerFunction": None,
    "ThnAuthAdminV2OwnerOperatorFunction": "requirements-tools.txt",
}


class ArtifactBuildError(RuntimeError):
    """The requested artifact cannot be assembled from the exact allowlist."""


def build_artifact(
    target: str,
    artifacts_dir: pathlib.Path | str,
    *,
    install_dependencies: bool = True,
) -> None:
    sources = SOURCE_ALLOWLIST.get(target)
    if sources is None:
        raise ArtifactBuildError("unknown Lambda artifact target")
    destination = pathlib.Path(artifacts_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ArtifactBuildError("Lambda artifact destination must be empty")

    for relative_name in sources:
        source = REPOSITORY_ROOT / relative_name
        if not source.is_file():
            raise ArtifactBuildError("allowlisted Lambda source is missing")
        copied_target = destination / relative_name
        copied_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, copied_target)

    if not install_dependencies:
        return
    requirements_name = RUNTIME_REQUIREMENTS.get(target)
    if requirements_name is None:
        return
    requirements = REPOSITORY_ROOT / requirements_name
    if not requirements.is_file():
        raise ArtifactBuildError("runtime requirements are missing")
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-compile",
                # Match template.yaml's Python 3.13 / default x86_64 Lambda,
                # not the build host (which may be Windows or macOS).
                "--platform",
                "manylinux2014_x86_64",
                "--implementation",
                "cp",
                "--python-version",
                "3.13",
                "--only-binary=:all:",
                "--requirement",
                str(requirements),
                "--target",
                str(destination),
            ],
            cwd=REPOSITORY_ROOT,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ArtifactBuildError("Lambda dependencies could not be installed") from error
    # pip creates console launchers for the host even with --platform. CFFI's
    # source-generation CLI is build tooling, not part of the Lambda runtime.
    for name in ("cffi-gen-src.exe", "cffi-gen-src"):
        launcher = destination / "bin" / name
        if launcher.exists():
            if launcher.is_symlink() or not launcher.is_file() or not launcher.resolve().is_relative_to(destination):
                raise ArtifactBuildError("unexpected linked console launcher")
            launcher.unlink()


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2:
        print("usage: build_lambda_artifact.py TARGET ARTIFACTS_DIR", file=sys.stderr)
        return 2
    try:
        build_artifact(arguments[0], arguments[1])
        return 0
    except ArtifactBuildError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
