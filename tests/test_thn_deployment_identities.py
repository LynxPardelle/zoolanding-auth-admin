import unittest,json,re
from pathlib import Path
from tools.thn_production_release import sha
class DeploymentIdentityManifestTests(unittest.TestCase):
 def manifest(self):return json.loads((Path(__file__).resolve().parents[1]/'tools/production/thn-deployment-identities.json').read_text())
 def test_retained_policies_stay_inside_iam_size_limits_and_existing_trust_preserved(self):
  value=self.manifest();resources=value['template']['Resources']
  for name,r in resources.items():
   self.assertEqual(r['DeletionPolicy'],'Retain',name);self.assertEqual(r['UpdateReplacePolicy'],'Retain',name)
   if r['Type']=='AWS::IAM::ManagedPolicy':self.assertLessEqual(len(json.dumps(r['Properties']['PolicyDocument'],separators=(',',':'))),5800,name)
   if r['Type']=='AWS::IAM::Role':self.assertLessEqual(len(r['Properties'].get('ManagedPolicyArns',[])),10,name)
  self.assertEqual(set(value['externalRolePolicyBaselines']),{'zoolanding-auth-admin-production-deploy','zoolanding-content-hub-production-deploy'})
  for r in resources.values():
   if r['Type']=='AWS::IAM::Role':self.assertNotIn(r['Properties']['RoleName'],value['externalRolePolicyBaselines'])
 def test_matrix_contains_only_valid_same_service_scopes_no_log_empty_or_pseudo_actions(self):
  value=self.manifest()
  for proof in value['proofMatrix']:
   for action in proof['actions']:
    self.assertRegex(action,r'^[a-z0-9-]+:[A-Za-z][A-Za-z0-9]*$')
    service=action.split(':')[0]
    for resource in proof['resources']:
     self.assertNotIn('log-group:/aws/lambda/:',resource)
     if resource!='*':
      expected='apigateway' if service=='apigateway' else service
      self.assertTrue(resource.startswith('arn:aws:'+expected+':'),(action,resource))
  self.assertFalse(any(a.startswith(('kms:','firehose:','s3files:')) for p in value['proofMatrix'] for a in p['actions']))
 def test_github_owner_metadata_requires_future_exact_physical_pool(self):
  value=self.manifest();resources=value['template']['Resources']
  for name,r in resources.items():
   if r['Type']!='AWS::IAM::Policy':continue
   for statement in r['Properties']['PolicyDocument']['Statement']:
    if any(a.startswith('cognito-idp:') for a in statement['Action']):
     self.assertEqual(r['Condition'],'HasVerifiedProductionOwnerPool')
     self.assertEqual(statement['Resource'],{'Ref':'ThnProductionOwnerPoolArn'})
  self.assertEqual(value['template']['Parameters']['ThnProductionOwnerPoolArn']['Default'],'BLOCKED')

 def test_generated_github_trust_uses_only_supported_aws_claims(self):
  value=self.manifest();count=0
  for r in value['template']['Resources'].values():
   if r['Type']=='AWS::IAM::Role' and r['Properties']['RoleName'].endswith('github-deploy'):
    count+=1;role=r['Properties']['RoleName'];repo='zoolanding-image-upload' if 'image-upload' in role else 'zoolanding-api-proxy'
    self.assertEqual(r['Properties']['AssumeRolePolicyDocument']['Statement'][0]['Condition'],{'StringEquals':{'token.actions.githubusercontent.com:aud':'sts.amazonaws.com','token.actions.githubusercontent.com:sub':f'repo:LynxPardelle/{repo}:environment:production'}})
  self.assertEqual(count,3)
  generator=(Path(__file__).resolve().parents[1]/'tools/build_thn_deployment_identities.py').read_text()
  self.assertNotIn('token.actions.githubusercontent.com:ref',generator)

 def test_external_api_function_role_is_in_native_pass_role_scope(self):
  from tools import build_thn_deployment_identities as generator
  role='zlp-thn-auth-runtime-prod-role'
  native={'Resources':{'ThnAuthRuntimeV2Function':{'Type':'AWS::Lambda::Function',
      'Properties':{'Role':f'arn:aws:iam::765932874577:role/{role}'}}}}
  self.assertTrue(callable(getattr(generator,'function_role_names',None)))
  self.assertEqual(generator.function_role_names(native,{}),[role])

 def test_api_runtime_role_is_retained_and_trusts_only_lambda(self):
  value=self.manifest();resources=value['template']['Resources']
  self.assertIn('ApiRuntimeRole',resources)
  role=resources['ApiRuntimeRole']
  self.assertEqual(role['Type'],'AWS::IAM::Role')
  self.assertEqual(role['Properties']['RoleName'],'zlp-thn-auth-runtime-prod-role')
  self.assertEqual(role['Properties']['AssumeRolePolicyDocument']['Statement'][0]['Principal'],
                   {'Service':'lambda.amazonaws.com'})
  api=next(group for group in value['groups'] if group['group']=='api')
  requirements={row['logicalId']:row for row in api['resourceRequirements']}
  self.assertNotIn('ThnAuthRuntimeV2FunctionRole',requirements)
  self.assertEqual(requirements['ThnAuthRuntimeV2Function']['nameOrApprovedGeneratedPrefix'],
                   'zlp-thn-auth-runtime-production')

 def test_api_slice_overlay_preserves_later_infra_resources_and_hub_policy(self):
  from tools import build_thn_deployment_identities as generator
  self.assertTrue(callable(getattr(generator,'overlay_api_manifest',None)))
  base=self.manifest()
  candidate=json.loads(json.dumps(base))
  candidate['template']['Resources']['ApiRuntimeRole']={'Type':'AWS::IAM::Role'}
  candidate['template']['Resources']['ApiCfnNativePolicy0']={'Type':'AWS::IAM::ManagedPolicy','Version':'new'}
  candidate['template']['Resources']['HubCfnNativePolicy2']={'Type':'AWS::IAM::ManagedPolicy','Version':'stale'}
  candidate['proofMatrix']=[p for p in candidate['proofMatrix'] if p['group']!='api']+[
      {'group':'api','actions':['iam:PassRole'],'resources':['exact-runtime-role']}]
  result=generator.overlay_api_manifest(base,candidate)
  self.assertEqual(result['template']['Resources']['ApiRuntimeRole'],candidate['template']['Resources']['ApiRuntimeRole'])
  self.assertEqual(result['template']['Resources']['ApiCfnNativePolicy0'],candidate['template']['Resources']['ApiCfnNativePolicy0'])
  self.assertEqual(result['template']['Resources']['HubCfnNativePolicy2'],base['template']['Resources']['HubCfnNativePolicy2'])
  self.assertEqual([p for p in result['proofMatrix'] if p['group']!='api'],
                   [p for p in base['proofMatrix'] if p['group']!='api'])
