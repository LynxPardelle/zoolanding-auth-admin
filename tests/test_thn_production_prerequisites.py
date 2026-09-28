import unittest
from tools.thn_production_prerequisites import validate_selection,verify_registry,REQUIRED_OWNERS
from tools.thn_production_release import ReleaseError
class ProductionPrerequisiteTests(unittest.TestCase):
    def selection(self):
        return {'schemaVersion':1,'environment':'production','service':'auth','sourceSha':'a'*40,'owners':{name:{'processedTemplateSha256':'b'*64,'originalTemplateSha256':'c'*64,'resourceInventorySha256':'d'*64} for name in REQUIRED_OWNERS},'registrySha256':'e'*64}
    def test_exact_owned_names_and_hashes_no_test_or_missing(self):
        validate_selection(self.selection(),'auth','a'*40)
        for mutation in ('test','owner','hash','source','extra'):
            value=self.selection()
            if mutation=='test':value['environment']='test'
            if mutation=='owner':value['owners']['zoolanding-content-hub-test']=value['owners'].pop('zoolanding-content-hub-prod')
            if mutation=='hash':value['registrySha256']='0'*64
            if mutation=='source':value['sourceSha']='f'*40
            if mutation=='extra':value['extra']=True
            with self.assertRaises(ReleaseError):validate_selection(value,'auth','a'*40)
    def test_registry_is_closed_exact_production_before_activation(self):
        row={'pk':'SERVICE_BINDING#production#thn-journal-production-v2','sk':'REGISTRY#V2','environment':'production','serviceBindingId':'thn-journal-production-v2','domain':'thehairnarrative.com','adminOrigin':'https://admin.thehairnarrative.com','cookieNamespace':'ltnafwb6videyraictgp','writerMode':'disabled','registryRevision':1,'writerEpoch':1}
        verify_registry(row)
        for field,value in [('environment','test'),('writerMode','qa-only'),('writerMode','client-owner'),('cookieNamespace','endefiz7dkk635k6di6k'),('registryRevision',True)]:
            with self.assertRaises(ReleaseError):verify_registry({**row,field:value})
