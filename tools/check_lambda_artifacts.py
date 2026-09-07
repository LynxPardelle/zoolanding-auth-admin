#!/usr/bin/env python3
"""Fail closed when SAM artifacts contain project sources outside their runtime."""

from __future__ import annotations

import pathlib
import sys
from collections.abc import Sequence

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from tools.build_lambda_artifact import REPOSITORY_ROOT, SOURCE_ALLOWLIST


FORBIDDEN_DIRECTORIES = frozenset({".github", "changelog", "docs", "tests", "tools"})
PROJECT_SOURCE_NAMES = frozenset(
    {
        "lambda_function.py",
        "auth_admin_current_user_v2.py",
        "auth_admin_session_v2.py",
        "auth_admin_origin_authorizer_v2.py",
        "auth_admin_owner_operator_v2.py",
        "service_binding_registry_consumer_v2.py",
        "provision_thn_owner.py",
        "template.yaml",
    }
)


class ArtifactValidationError(RuntimeError):
    """A built Lambda artifact crossed a source or function boundary."""


def validate_artifact(target: str, artifact_dir: pathlib.Path | str) -> None:
    allowed = SOURCE_ALLOWLIST.get(target)
    if allowed is None:
        raise ArtifactValidationError("unknown Lambda artifact target")
    root = pathlib.Path(artifact_dir).resolve()
    if not root.is_dir():
        raise ArtifactValidationError("Lambda artifact is missing")
    names = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }
    allowed_names = set(allowed)
    missing = allowed_names - names
    forbidden = {
        name
        for name in names
        if (
            name.split("/", 1)[0] in FORBIDDEN_DIRECTORIES
            or pathlib.PurePosixPath(name).name in PROJECT_SOURCE_NAMES
        )
        and name not in allowed_names
    }
    foreign_binaries = {name for name in names if pathlib.PurePosixPath(name).suffix.lower() in {".pyd", ".dll", ".exe", ".pyc"}}
    if missing or forbidden or foreign_binaries:
        raise ArtifactValidationError("Lambda artifact allowlist mismatch")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    build_root = REPOSITORY_ROOT / ".aws-sam" / "build"
    targets = list(SOURCE_ALLOWLIST) if not arguments else arguments
    try:
        for target in targets:
            validate_artifact(target, build_root / target)
        return 0
    except ArtifactValidationError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
