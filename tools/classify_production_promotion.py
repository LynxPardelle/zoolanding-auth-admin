"""Credential-free selection of the exact reviewed TEST -> main merge.

There is deliberately no legacy fallback during this coordinated THN release.
"""
import json
import os
import re
import sys

COORDINATES = ("sourceSha", "sourceTree", "targetBaseSha", "mergeTree")
FIELDS = {"schemaVersion", "mode", *COORDINATES}
class PromotionSelectionError(ValueError):
    pass

def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise PromotionSelectionError("production_selection_invalid")
        result[key] = value
    return result

def _git(value):
    return isinstance(value,str) and bool(re.fullmatch(r"[a-f0-9]{40}",value)) and value != "0"*40

def classify_selection(raw, *, sourceSha, sourceTree, targetBaseSha, mergeTree):
    context = dict(sourceSha=sourceSha,sourceTree=sourceTree,targetBaseSha=targetBaseSha,mergeTree=mergeTree)
    if not all(_git(value) for value in context.values()):
        raise PromotionSelectionError("production_context_invalid")
    try:
        if not isinstance(raw,str) or not raw or len(raw.encode('utf-8'))>4096: raise ValueError()
        value = json.loads(raw,object_pairs_hook=_object)
        if not isinstance(value,dict) or set(value)!=FIELDS or type(value['schemaVersion']) is not int or value['schemaVersion']!=1 or value['mode']!='thn-source-only' or not all(_git(value[key]) for key in COORDINATES): raise ValueError()
    except (ValueError,UnicodeError,RecursionError):
        raise PromotionSelectionError("production_selection_invalid") from None
    if any(value[key]!=context[key] for key in COORDINATES):
        raise PromotionSelectionError("production_selection_stale")
    return "thn-source-only"

def main(argv=None):
    try:
        if sys.argv[1:] if argv is None else argv: raise PromotionSelectionError("production_arguments_invalid")
        mode=classify_selection(os.environ.get("PRODUCTION_PROMOTION_SELECTION_JSON"), **{key:os.environ.get("PROMOTED_"+re.sub(r"([a-z])([A-Z])",r"\1_\2",key).upper()) for key in COORDINATES})
    except PromotionSelectionError as error:
        print(str(error),file=sys.stderr)
        return 2
    print(mode)
    return 0
if __name__=='__main__': raise SystemExit(main())
