import json
import unittest
from tools.classify_production_promotion import classify_selection, PromotionSelectionError

CONTEXT = dict(sourceSha="a"*40,sourceTree="b"*40,targetBaseSha="c"*40,mergeTree="d"*40)
class ProductionPromotionSelectionTests(unittest.TestCase):
    def selection(self, **updates):
        return json.dumps(dict(schemaVersion=1,mode="thn-source-only",**CONTEXT,**updates))
    def test_exact_source_only_selection(self):
        self.assertEqual(classify_selection(self.selection(), **CONTEXT), "thn-source-only")
    def test_missing_selection_never_deploys(self):
        for raw in (None,"","{}"):
            with self.assertRaises(PromotionSelectionError): classify_selection(raw, **CONTEXT)
    def test_every_coordinate_is_pinned(self):
        for key in CONTEXT:
            value=json.loads(self.selection());value[key]="e"*40
            with self.assertRaises(PromotionSelectionError): classify_selection(json.dumps(value), **CONTEXT)
    def test_duplicates_unknown_fields_and_legacy_are_closed(self):
        valid=self.selection()
        for raw in (valid[:-1]+',"sourceSha":"'+"a"*40+'"}', valid[:-1]+',"other":1}', valid.replace("thn-source-only","legacy")):
            with self.assertRaises(PromotionSelectionError): classify_selection(raw, **CONTEXT)
    def test_context_and_schema_are_strict(self):
        for bad in ("0"*40,"A"*40,"short"):
            context=dict(CONTEXT);context['sourceSha']=bad
            with self.assertRaises(PromotionSelectionError): classify_selection(self.selection(), **context)
        value=json.loads(self.selection());value['schemaVersion']=True
        with self.assertRaises(PromotionSelectionError): classify_selection(json.dumps(value), **CONTEXT)
