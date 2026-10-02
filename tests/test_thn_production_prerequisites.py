import unittest
from unittest.mock import patch
from boto3.dynamodb.types import TypeSerializer
from tools import thn_production_release as release
from tools.thn_production_prerequisites import capture,validate_selection,verify_registry,REQUIRED_OWNERS
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

    def test_capture_hashes_dynamodb_integer_schema_version_like_plain_registry_row(self):
        row={'pk':'SERVICE_BINDING#production#thn-journal-production-v2','sk':'REGISTRY#V2','schemaVersion':2,
             'environment':'production','serviceBindingId':'thn-journal-production-v2','domain':'thehairnarrative.com',
             'adminOrigin':'https://admin.thehairnarrative.com','cookieNamespace':'ltnafwb6videyraictgp',
             'writerMode':'disabled','registryRevision':1,'writerEpoch':1}
        serialized={key:TypeSerializer().serialize(value) for key,value in row.items()}
        baselines={}
        for name,required in REQUIRED_OWNERS.items():
            resources=[{'LogicalResourceId':logical,'ResourceType':kind,
                        'PhysicalResourceId':('us-east-1_example' if logical=='ThnAuthAdminV2UserPool'
                                              else 'zoolanding-content-hub-prod-ServiceBindingRegistryV2' if logical=='ServiceBindingRegistryV2Table'
                                              else f'{name}-{logical}')}
                       for logical,kind in required.items()]
            baselines[name]={'terminationProtection':True,'status':'UPDATE_COMPLETE',
                             'processed':{},'original':{},'resources':resources}
        selection={'schemaVersion':1,'environment':'production','service':'auth',
                   'sourceSha':'a'*40,
                   'owners':{name:{'processedTemplateSha256':release.sha({}),
                                    'originalTemplateSha256':release.sha({}),
                                    'resourceInventorySha256':release.sha(baseline['resources'])}
                             for name,baseline in baselines.items()},
                   'registrySha256':release.sha(row)}

        class Cognito:
            def describe_user_pool(self,**kwargs):
                return {'UserPool':{'Name':'zoolanding-auth-admin-prod-ThnAuthAdminV2',
                                    'MfaConfiguration':'ON','DeletionProtection':'ACTIVE',
                                    'AdminCreateUserConfig':{'AllowAdminCreateUserOnly':True}}}
            def get_user_pool_mfa_config(self,**kwargs):
                return {'MfaConfiguration':'ON','SoftwareTokenMfaConfiguration':{'Enabled':True}}
        class Dynamo:
            def get_item(self,**kwargs):
                return {'Item':serialized}
        class Session:
            def client(self,name):
                return {'cloudformation':object(),'cognito-idp':Cognito(),'dynamodb':Dynamo()}[name]
        with patch('tools.thn_production_prerequisites.release.snapshot',side_effect=lambda cf,name:baselines[name]):
            actual=capture(Session(),selection,'auth','a'*40)
        self.assertEqual(actual['registrySha256'],selection['registrySha256'])
