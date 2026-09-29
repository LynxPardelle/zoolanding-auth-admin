import copy
import unittest
from tools.thn_production_release import ReleaseError, make_review_record, verify_review_record, review_inventory, select_parameters
class RetainedProductionReleaseTests(unittest.TestCase):
    def record(self):
        return make_review_record(service='auth',purpose='state',source_sha='a'*40,stack_id='arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-auth-admin-prod/id',change_set_arn='arn:aws:cloudformation:us-east-1:765932874577:changeSet/thn-production-auth-state/id',created_at=1000,baseline={'resources':[]},original={'Resources':{}},processed={'Resources':{}},parameters=[],packages=[{'bucket':'bucket','key':'key','versionId':'v1','sha256':'b'*64}],changes=[],recovery=[])
    def test_sealed_exact_review_all_fields_and_expiry(self):
        r=self.record(); verify_review_record(r,approved_digest=r['digest'],now=1001,service='auth',source_sha='a'*40)
        for key in ('purpose','baselineSha256','changeSetArn','stackId','packageManifest','changes','expiresAt'):
            bad=copy.deepcopy(r);bad[key]=None
            with self.assertRaises(ReleaseError): verify_review_record(bad,approved_digest=r['digest'],now=1001,service='auth',source_sha='a'*40)
        with self.assertRaises(ReleaseError): verify_review_record(r,approved_digest=r['digest'],now=87401,service='auth',source_sha='a'*40)
        with self.assertRaises(ReleaseError): verify_review_record({**r,'unknown':1},approved_digest=r['digest'],now=1001,service='auth',source_sha='a'*40)
    def test_no_resource_deletion_or_identity_replacement(self):
        old={'Resources':{'F':{'Type':'AWS::Lambda::Function','Properties':{'FunctionName':'same'}}}}
        for replacement in ('True','Conditional'):
            changes=[{'ResourceChange':{'Action':'Modify','LogicalResourceId':'F','ResourceType':'AWS::Lambda::Function','Replacement':replacement}}]
            with self.assertRaises(ReleaseError): review_inventory(changes,old,old,scope='general')
        with self.assertRaises(ReleaseError): review_inventory([{'ResourceChange':{'Action':'Remove','LogicalResourceId':'F','ResourceType':'AWS::Lambda::Function'}}],old,old,scope='general')
    def test_conditional_dependency_requires_identical_native_properties(self):
        old={'Resources':{'P':{'Type':'AWS::Lambda::Permission','Properties':{'Action':'lambda:InvokeFunction','Principal':'exact'}}}}
        c=[{'ResourceChange':{'Action':'Modify','LogicalResourceId':'P','ResourceType':'AWS::Lambda::Permission','Replacement':'Conditional'}}]
        review_inventory(c,old,old,scope='general')
        new=copy.deepcopy(old);new['Resources']['P']['Properties']['Principal']='*'
        with self.assertRaises(ReleaseError): review_inventory(c,old,new,scope='general')
    def test_new_state_requires_retention_and_protection(self):
        c=[{'ResourceChange':{'Action':'Add','LogicalResourceId':'ThnState','ResourceType':'AWS::DynamoDB::Table'}}]
        new={'Resources':{'ThnState':{'Type':'AWS::DynamoDB::Table','Properties':{}}}}
        with self.assertRaises(ReleaseError): review_inventory(c,{'Resources':{}},new,scope='state')
        new['Resources']['ThnState'].update(DeletionPolicy='Retain',UpdateReplacePolicy='Retain');new['Resources']['ThnState']['Properties'].update(DeletionProtectionEnabled=True,PointInTimeRecoverySpecification={'PointInTimeRecoveryEnabled':True})
        review_inventory(c,{'Resources':{}},new,scope='state')
    def test_parameters_preserve_legacy_secret_and_block_unknown_or_test(self):
        definitions={'LegacySecret':{'NoEcho':True},'EnableThnAuthAdminV2':{'Default':'false'},'ProvisionThnAuthAdminV2State':{'Default':'false'},'EnvironmentName':{'Default':'prod'}}
        result=select_parameters(definitions,[{'ParameterKey':'LegacySecret','ParameterValue':'****'}],{'ProvisionThnAuthAdminV2State':'true'},purpose='state')
        self.assertIn({'ParameterKey':'LegacySecret','UsePreviousValue':True},result)
        self.assertIn({'ParameterKey':'EnableThnAuthAdminV2','ParameterValue':'false'},result)
        with self.assertRaises(ReleaseError): select_parameters(definitions,[],{'EnvironmentName':'test'},purpose='state')
        with self.assertRaises(ReleaseError): select_parameters(definitions,[],{'Unknown':'x'},purpose='state')

    def test_general_preserves_active_private_routes_and_rejects_toggling(self):
        definitions={'EnableThnAuthAdminV2':{'Default':'false'}}
        previous=[{'ParameterKey':'EnableThnAuthAdminV2','ParameterValue':'true'}]
        self.assertEqual(select_parameters(definitions,previous,{},purpose='general'),[{'ParameterKey':'EnableThnAuthAdminV2','UsePreviousValue':True}])
        with self.assertRaises(ReleaseError):select_parameters(definitions,previous,{'EnableThnAuthAdminV2':'false'},purpose='general')

    def test_hub_generated_stage_requires_correct_api_owner(self):
        stage={'Type':'AWS::ApiGatewayV2::Stage','Properties':{'ApiId':{'Ref':'ContentHubApi'},'StageName':'prod'}}
        c=[{'ResourceChange':{'Action':'Modify','LogicalResourceId':'ContentHubApiprodStage','ResourceType':stage['Type'],'Replacement':'False'}}]
        review_inventory(c,{'Resources':{}},{'Resources':{'ContentHubApiprodStage':stage}},scope='activate')
        bad=copy.deepcopy(stage);bad['Properties']['ApiId']={'Ref':'OtherApi'}
        with self.assertRaises(ReleaseError):review_inventory(c,{'Resources':{}},{'Resources':{'ContentHubApiprodStage':bad}},scope='activate')

    def test_retained_execute_only_exact_preview_and_all_fingerprints(self):
        from tools.thn_production_release import execute_retained,sha,canonical
        import io
        changes=[{'ResourceChange':{'Action':'Modify','LogicalResourceId':'ThnFn','ResourceType':'AWS::Lambda::Function','Replacement':'False'}}]
        template={'Resources':{'ThnFn':{'Type':'AWS::Lambda::Function','Properties':{'FunctionName':'same'}}}}
        baseline={'processed':template};permissions={'allowed':True};identity={'role':'exact'};source={'sha':'main'}
        body=b'private immutable bytes';package={'bucket':'private','key':'thn/production/auth/a','versionId':'v1','sha256':sha(body)}
        r=make_review_record(service='auth',purpose='activate',source_sha='a'*40,stack_id=self.record()['stackId'],change_set_arn=self.record()['changeSetArn'],created_at=1000,baseline=baseline,original=template,processed=template,parameters=[],packages=[package],changes=changes,recovery=[],permissions=permissions,identity=identity,source_package=source)
        class CF:
            def __init__(self):self.executed=[];self.template=copy.deepcopy(template);self.changes=copy.deepcopy(changes);self.stack=r['stackId']
            def describe_change_set(self,**kw):return {'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE','StackId':self.stack,'Changes':self.changes,'Parameters':[]}
            def get_template(self,**kw):return {'TemplateBody':self.template}
            def execute_change_set(self,**kw):self.executed.append(kw)
        class S3:
            data=body
            def get_object(self,**kw):return {'Body':io.BytesIO(self.data)}
        for mutation in ('none','baseline','permissions','identity','source','bytes','inventory','template','stack'):
            cf=CF();s3=S3();arguments=dict(baseline=copy.deepcopy(baseline),permissions=permissions,identity=identity,source_package=source)
            if mutation in ('baseline','permissions','identity'):arguments[mutation]={'changed':True}
            if mutation=='source':arguments['source_package']={'changed':True}
            if mutation=='bytes':s3.data=b'changed'
            if mutation=='inventory':cf.changes[0]['ResourceChange']['Scope']=['Properties']
            if mutation=='template':cf.template['Resources']['ThnFn']['Properties']['FunctionName']='changed'
            if mutation=='stack':cf.stack+='changed'
            if mutation=='none':
                execute_retained(cf,s3,r,approved_digest=r['digest'],source_sha='a'*40,service='auth',now=1001,authority_check=lambda:None,**arguments)
                self.assertEqual(cf.executed,[{'ChangeSetName':r['changeSetArn'],'StackName':r['stackId']}])
            else:
                with self.assertRaises(ReleaseError):execute_retained(cf,s3,r,approved_digest=r['digest'],source_sha='a'*40,service='auth',now=1001,authority_check=lambda:None,**arguments)
                self.assertEqual(cf.executed,[])

class EffectivePermissionDriverTests(unittest.TestCase):
    def test_simulation_uses_real_request_context_not_unrelated_policy_union(self):
        import os,json
        from unittest.mock import Mock,patch
        import boto3
        from botocore.validate import validate_parameters
        from tools import run_thn_production_release as driver
        config=driver.CONFIG;account='765932874577';caller=f"arn:aws:iam::{account}:role/{config['deployRole']}";execution=f"arn:aws:iam::{account}:role/{config['executionRole']}"
        conditions={'token.actions.githubusercontent.com:aud':'sts.amazonaws.com','token.actions.githubusercontent.com:sub':f"repo:LynxPardelle/{config['repository']}:environment:production"}
        roles={config['deployRole']:{'Arn':caller,'AssumeRolePolicyDocument':{'Statement':[{'Effect':'Allow','Action':'sts:AssumeRoleWithWebIdentity','Principal':{'Federated':f'arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com'},'Condition':{'StringEquals':conditions}}]}},config['executionRole']:{'Arn':execution,'AssumeRolePolicyDocument':{'Statement':[{'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'Service':'cloudformation.amazonaws.com'}}]}}}
        iam=Mock();iam.get_role.side_effect=lambda **kw:{'Role':roles[kw['RoleName']]}
        shape=boto3.Session(region_name='us-east-1')._session.get_service_model('iam').operation_model('GetContextKeysForPrincipalPolicy').input_shape
        def contexts(**kwargs):
            validate_parameters(kwargs,shape)
            return {'ContextKeyNames':['s3:prefix']}
        iam.get_context_keys_for_principal_policy.side_effect=contexts
        iam.simulate_principal_policy.side_effect=lambda **kw:{'EvaluationResults':[{'EvalActionName':a,'EvalDecision':'allowed','ResourceSpecificResults':[{'EvalResourceName':r,'EvalResourceDecision':'allowed'} for r in kw['ResourceArns']]} for a in kw['ActionNames']]}
        iam.get_paginator.return_value.paginate.return_value=[]
        session=Mock(region_name='us-east-1');sts=Mock();sts.get_caller_identity.return_value={'Account':account,'Arn':f"arn:aws:sts::{account}:assumed-role/{config['deployRole']}/run"};session.client.side_effect=lambda name:{'iam':iam,'sts':sts}[name]
        requests=[{'principalArn':caller,'actions':sorted(driver.CALLER_ACTIONS),'resources':['*'],'context':[]},{'principalArn':execution,'actions':['lambda:GetFunction'],'resources':['arn:aws:lambda:us-east-1:765932874577:function:production','arn:aws:lambda:us-east-1:765932874577:function:production:4'],'context':[]}]
        plan={'schemaVersion':1,'environment':'production','service':config['service'],'purpose':'state','sourceSha':'a'*40,'requests':requests}
        with patch.dict(os.environ,{'THN_PRODUCTION_PERMISSION_PLAN_JSON':json.dumps(plan)}):
            driver.identity_and_permissions(session,{'sourceSha':'a'*40},'state')
        iam.get_context_keys_for_principal_policy.assert_not_called()
        self.assertEqual(iam.simulate_principal_policy.call_count,2)
        # AWS may return one action summary with nested per-resource decisions.
        # A missing or duplicated resource must not look like a complete proof.
        for malformed in ('missing','duplicate','denied','context','resource-context','truncated'):
            def incomplete(**kwargs):
                rows=[{'EvalActionName':a,'EvalDecision':'allowed','ResourceSpecificResults':[{'EvalResourceName':r,'EvalResourceDecision':'allowed'} for r in kwargs['ResourceArns']]} for a in kwargs['ActionNames']]
                result={'EvaluationResults':rows}
                if malformed=='missing':rows[0]['ResourceSpecificResults']=[]
                elif malformed=='duplicate':rows[0]['ResourceSpecificResults']*=2
                elif malformed=='denied':rows[0]['ResourceSpecificResults'][0]['EvalResourceDecision']='explicitDeny'
                elif malformed=='context':rows[0]['MissingContextValues']=['reviewed-context']
                elif malformed=='resource-context':rows[0]['ResourceSpecificResults'][0]['MissingContextValues']=['reviewed-context']
                else:result['IsTruncated']=True
                return result
            iam.simulate_principal_policy.side_effect=incomplete
            with self.subTest(response=malformed),patch.dict(os.environ,{'THN_PRODUCTION_PERMISSION_PLAN_JSON':json.dumps(plan)}):
                with self.assertRaises(ReleaseError):
                    driver.identity_and_permissions(session,{'sourceSha':'a'*40},'state')
        for call,request in zip(iam.simulate_principal_policy.call_args_list[:2],requests):
            self.assertEqual(call.kwargs['ActionNames'],[a.lower() for a in request['actions']])
            self.assertEqual(call.kwargs['ResourceArns'],request['resources'])
            self.assertEqual(call.kwargs['ContextEntries'],request['context'])
        self.assertEqual(requests[1]['actions'],['lambda:GetFunction'])
    def test_final_authority_recaptures_environment_after_package_reads(self):
        from unittest.mock import Mock,patch
        from tools import run_thn_production_release as driver
        from tools.thn_production_release import sha,ReleaseError
        source={'sourceSha':'a'*40};baseline={'processed':{'Resources':{}},'identity':'stable'};identity={'role':'same'};permissions={'allowed':True};session=Mock();preview={'Changes':[]}
        record={'baselineSha256':sha(baseline),'permissionSha256':sha(permissions),'identitySha256':sha(identity),'sourcePackageSha256':sha(source)}
        for field in ('none','baseline','identity','permissions','source'):
            fresh_baseline=baseline if field!='baseline' else {'processed':{'Resources':{}},'identity':'changed'}
            fresh_identity=identity if field!='identity' else {'role':'changed'}
            fresh_permissions=permissions if field!='permissions' else {'denied':True}
            fresh_source=source if field!='source' else {'sourceSha':'b'*40}
            with patch.object(driver,'source_selection',return_value=fresh_source),patch.object(driver,'captured_baseline',return_value=fresh_baseline),patch.object(driver,'identity_and_permissions',return_value=(fresh_identity,fresh_permissions)):
                if field=='none':driver.fresh_execute_authority(session,record,source,'state',preview,{'Resources':{}})
                else:
                    with self.assertRaises(ReleaseError):driver.fresh_execute_authority(session,record,source,'state',preview,{'Resources':{}})
