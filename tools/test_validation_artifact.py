"""Create/verify NONDEPLOYABLE TEST validation transport using trusted source code.

No AWS SDK, deployment parameters, executable release helpers, or artifact-owned
verifier are included. The expected manifest digest is supplied by the build job.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.build_lambda_artifact import SOURCE_ALLOWLIST
from tools.check_lambda_artifacts import ArtifactValidationError, validate_artifact

SCHEMA = "zoolanding-test-validation/v1"
METADATA = "validation-metadata.json"
CONTEXT_KEYS = {"source_sha", "dev_sha", "dev_tree", "run_id", "run_attempt"}
MAX_MANIFEST_BYTES = 2_000_000
MAX_FILES = 10000
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


class ValidationArtifactError(ValueError):
    """Only fixed diagnostics may cross the CLI boundary."""


def _fail():
    raise ValidationArtifactError("validation_artifact_invalid")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _constant(_value):
    _fail()


def _json(path, limit):
    if path.stat().st_size > limit:
        _fail()
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        _fail()


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _metadata(context):
    if not isinstance(context, dict) or set(context) != CONTEXT_KEYS:
        _fail()
    for key, value in context.items():
        pattern = r"[a-f0-9]{40}" if key.endswith(("sha", "tree")) else r"[1-9][0-9]{0,19}"
        if not isinstance(value, str) or not re.fullmatch(pattern, value) or value == "0" * 40:
            _fail()
    return dict(context, schema=SCHEMA, service="zoolanding-auth-admin", purpose="validation-only",
                deployable=False, promotion_mode="thn-source-only")


def _regular(path, directory=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        _fail()  # Reject Windows reparse points as well as POSIX links.
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        _fail()


def _digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inventory(build, with_metadata):
    _regular(build, directory=True)
    allowed = set(SOURCE_ALLOWLIST) | {"template.yaml"} | ({METADATA} if with_metadata else set())
    if {path.name for path in build.iterdir()} != allowed:
        _fail()
    _regular(build / "template.yaml")
    files, total, pending = {}, 0, [build]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            relative = path.relative_to(build).as_posix()
            if any(ord(char) < 32 or ord(char) > 126 for char in relative) or "\\" in relative or ":" in relative:
                _fail()
            info = path.lstat()
            is_directory = stat.S_ISDIR(info.st_mode)
            _regular(path, directory=is_directory)
            if is_directory:
                pending.append(path)
                continue
            total += info.st_size
            if len(files) >= MAX_FILES or total > MAX_ARTIFACT_BYTES:
                _fail()
            files[relative] = _digest(path)
    for target, sources in SOURCE_ALLOWLIST.items():
        try:
            validate_artifact(target, build / target)
        except ArtifactValidationError:
            _fail()
        # A transported project file must still be the exact checked-out source.
        for source in sources:
            if files.get(f"{target}/{source}") != _digest(ROOT / source):
                _fail()
    return files


def create_artifact(build, manifest, context):
    build, manifest = Path(build), Path(manifest)
    metadata = _metadata(context)
    if manifest.exists() or manifest.is_symlink() or manifest.parent.resolve() != build.parent.resolve() or manifest.name != "validation-manifest.json":
        _fail()
    files = _inventory(build, with_metadata=False)
    payload = _bytes(metadata)
    files[METADATA] = hashlib.sha256(payload).hexdigest()
    manifest_payload = _bytes({"schema": SCHEMA, "files": files})
    if len(manifest_payload) > MAX_MANIFEST_BYTES:
        _fail()
    with (build / METADATA).open("xb") as stream:
        stream.write(payload)
    with manifest.open("xb") as stream:
        stream.write(manifest_payload)
    return hashlib.sha256(manifest_payload).hexdigest()


def verify_artifact(build, manifest, expected_digest, context):
    build, manifest = Path(build), Path(manifest)
    expected_metadata = _metadata(context)
    if not isinstance(expected_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
        _fail()
    if manifest.parent.resolve() != build.parent.resolve() or manifest.name != "validation-manifest.json":
        _fail()
    if {path.name for path in build.parent.iterdir()} != {build.name, manifest.name}:
        _fail()
    _regular(manifest)
    if manifest.stat().st_size > MAX_MANIFEST_BYTES or _digest(manifest) != expected_digest:
        _fail()
    declared = _json(manifest, MAX_MANIFEST_BYTES)
    if not isinstance(declared, dict) or set(declared) != {"schema", "files"} or declared["schema"] != SCHEMA:
        _fail()
    actual = _inventory(build, with_metadata=True)
    if declared["files"] != actual:
        _fail()
    metadata = _json(build / METADATA, 4096)
    if not isinstance(metadata, dict) or metadata.get("deployable") is not False or metadata != expected_metadata:
        _fail()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        if len(argv) != 3 or argv[0] not in {"create", "verify"}:
            _fail()
        context = {key: os.environ.get("EXPECTED_" + key.upper()) for key in CONTEXT_KEYS}
        if argv[0] == "create":
            print(create_artifact(argv[1], argv[2], context))
        else:
            verify_artifact(argv[1], argv[2], os.environ.get("EXPECTED_MANIFEST_SHA256"), context)
            print("validation_artifact_verified")
    except (ValidationArtifactError, ArtifactValidationError, OSError, ValueError, RecursionError):
        print("validation_artifact_invalid", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
