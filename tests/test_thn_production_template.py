import copy
from pathlib import Path
import unittest
import yaml
from tools.prepare_thn_production_template import prepare_template
ROOT=Path(__file__).resolve().parents[1]
class ProductionTemplateTests(unittest.TestCase):
    def source(self): return yaml.safe_load((ROOT/'template.yaml').read_text())
    def test_v1_resources_are_preserved_byte_semantically(self):
        source=self.source();result=prepare_template(source)
        for logical,value in source['Resources'].items():
            if not logical.startswith('ThnAuthAdminV2'):
                self.assertEqual(result['Resources'][logical],value,logical)
    def test_production_resources_are_retained_isolated_and_disabled(self):
        result=prepare_template(self.source());body=yaml.safe_dump(result)
        self.assertNotIn('zoolanding-auth-admin-test',body)
        self.assertNotIn('zoolanding-content-hub-test',body)
        self.assertNotIn('SERVICE_BINDING#test#',body)
        self.assertNotIn('CURRENT_USER#test#',body)
        self.assertFalse(any(name.startswith('ThnAuthAdminV2OwnerOperator') for name in result['Resources']))
        self.assertEqual(result['Parameters']['ProvisionThnProductionOwnerOperatorV2']['Default'],'false')
        self.assertEqual(result['Resources']['ThnProductionOwnerOperatorV2Function']['Properties']['Handler'],'auth_admin_production_owner_operator_v2.lambda_handler')
        for parameter in ('EnableThnAuthAdminV2','ProvisionThnAuthAdminV2State'):
            self.assertEqual(result['Parameters'][parameter]['Default'],'false')
        for logical,value in result['Resources'].items():
            if logical.startswith('ThnAuthAdminV2') and value['Type'] in {'AWS::DynamoDB::Table','AWS::Cognito::UserPool','AWS::Cognito::UserPoolClient','AWS::Logs::LogGroup'}:
                self.assertEqual(value['DeletionPolicy'],'Retain',logical)
                self.assertEqual(value['UpdateReplacePolicy'],'Retain',logical)
        variables=result['Resources']['ThnAuthAdminV2Function']['Properties']['Environment']['Variables']
        self.assertEqual(variables['THN_DEPLOYMENT_ENVIRONMENT'],'production')
        self.assertEqual(result['Resources']['ThnAuthAdminV2Api']['Properties']['StageName'],'prod')
    def test_source_is_not_mutated(self):
        source=self.source();before=copy.deepcopy(source);prepare_template(source);self.assertEqual(source,before)
    def test_unrecognized_test_identity_is_rejected(self):
        source=self.source();source['Resources']['ThnAuthAdminV2Function']['Properties']['Environment']['Variables']['BAD']='zoolanding-unknown-test-secret'
        with self.assertRaises(ValueError): prepare_template(source)

    def test_native_translation_for_closed_and_active_resource_shapes(self):
        import os
        from unittest.mock import patch
        from samtranslator.translator.transform import transform
        for enabled in ('false','true'):
            candidate=prepare_template(self.source())
            for item in candidate['Resources'].values():
                if item['Type']=='AWS::Serverless::Function':
                    item['Properties']['CodeUri']={'Bucket':'synthetic-package','Key':'reviewed.zip','Version':'synthetic-version'}
            parameters={name:value.get('Default') for name,value in candidate['Parameters'].items() if 'Default' in value}
            parameters.update(ThnProductionOwnerHumanPrincipalArn='arn:aws:iam::765932874577:user/synthetic',ProvisionThnProductionOwnerOperatorV2='true',EnvironmentName='prod',CognitoUserPoolArns=['arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_synthetic'],EnableThnAuthAdminV2=enabled,ProvisionThnAuthAdminV2State='true',ThnAuthAdminV2TerminationProtectionGate='CONFIRMED_ENABLED',ThnProductionOwnerOperatorGate='CONFIRMED_PRODUCTION_OWNER_OPERATOR',ThnAuthAdminV2DescriptorVersionId='synthetic-production-v1',ThnAuthAdminV2DescriptorSha256='a'*64,ThnAuthAdminV2AuthPolicyVersion='synthetic-production-v1',ThnAuthAdminV2OriginHeaderSha256Current='b'*64)
            with patch.dict(os.environ,{'AWS_DEFAULT_REGION':'us-east-1'}):
                native=transform(candidate,parameters,{'AWSLambdaBasicExecutionRole':'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'})
            self.assertNotIn('Transform',native)
            self.assertTrue(all(not value['Type'].startswith('AWS::Serverless::') for value in native['Resources'].values()))
    def test_operator_human_role_is_separate_mfa_guarded_and_closed(self):
        candidate=prepare_template(self.source())
        role=candidate['Resources']['ThnProductionOwnerHumanOperatorRole']
        self.assertEqual(role['Properties']['RoleName'],'zoolanding-thn-owner-production-operator')
        trust=role['Properties']['AssumeRolePolicyDocument']['Statement'][0]
        self.assertEqual(trust['Principal'],{'AWS':{'Ref':'ThnProductionOwnerHumanPrincipalArn'}})
        self.assertEqual(trust['Condition']['Bool'],{'aws:MultiFactorAuthPresent':'true'})
        self.assertEqual(candidate['Parameters']['ThnProductionOwnerHumanPrincipalArn']['Default'],'BLOCKED')
        self.assertEqual(role['DeletionPolicy'],'Retain')
