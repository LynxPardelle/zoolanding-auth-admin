"""Fail-closed, credential-free selection of one exact TEST source promotion."""
import json
import os
import re
import sys


MAX_SELECTION_BYTES = 4096
FIELDS = {"schemaVersion", "mode", "devSha", "devTree"}


class PromotionSelectionError(ValueError):
    """A fixed diagnostic deliberately excludes configuration contents."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PromotionSelectionError("promotion_selection_invalid")
        result[key] = value
    return result


def _constant(_value):
    raise PromotionSelectionError("promotion_selection_invalid")


def _git_object(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{40}", value) and value != "0" * 40


def classify_selection(raw, dev_sha, dev_tree):
    """Absent selection preserves legacy; a defined selection must match exactly."""
    if not _git_object(dev_sha) or not _git_object(dev_tree):
        raise PromotionSelectionError("promotion_context_invalid")
    if raw is None or raw == "":
        return "legacy"
    try:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_SELECTION_BYTES:
            raise PromotionSelectionError("promotion_selection_invalid")
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise PromotionSelectionError("promotion_selection_invalid") from None
    if (
        not isinstance(value, dict)
        or set(value) != FIELDS
        or type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != 1
        or value["mode"] != "thn-source-only"
        or not _git_object(value["devSha"])
        or not _git_object(value["devTree"])
    ):
        raise PromotionSelectionError("promotion_selection_invalid")
    if value["devSha"] != dev_sha or value["devTree"] != dev_tree:
        raise PromotionSelectionError("promotion_selection_stale")
    return "thn-source-only"


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    try:
        if argv:
            raise PromotionSelectionError("promotion_arguments_invalid")
        mode = classify_selection(
            os.environ.get("AUTH_TEST_PROMOTION_SELECTION_JSON"),
            os.environ.get("PROMOTED_DEV_SHA"),
            os.environ.get("PROMOTED_DEV_TREE"),
        )
    except PromotionSelectionError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
