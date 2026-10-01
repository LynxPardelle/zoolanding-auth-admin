"""Offline compiler of the closed backend deployment-identity bootstrap.

Reads sanitized AWS CLI evidence and the five reviewed SAM projections. It does
not contact AWS or alter any role. Output is a source file reviewed with Infra.
"""
import argparse,json,re,sys,subprocess
from copy import deepcopy
from pathlib import Path
from tools.thn_production_release import sha,require,ACCOUNT,REGION
ROOT=Path(__file__).resolve().parents[1]
GROUPS={
 'auth':('zoolanding-auth-admin-thn-guard-integration','zoolanding-auth-admin','zoolanding-auth-admin-prod','zoolanding-auth-admin-production-deploy','zoolanding-deployer-auth-admin-production-cfn-exec','template.yaml'),
 'hub':('zoolanding-content-hub-thn-guard-integration','zoolanding-content-hub','zoolanding-content-hub-prod','zoolanding-content-hub-production-deploy','zoolanding-deployer-content-hub-production-cfn-exec','template.yaml'),
 'image':('zoolanding-image-upload-thn-finalize-fix','zoolanding-image-upload','zoolanding-image-upload','zoolanding-deployer-image-upload-production-github-deploy','zoolanding-deployer-image-upload-production-cfn-exec','template.yaml'),
 'api':('zoolanding-api-proxy-thn-guard-integration','zoolanding-api-proxy','zoolanding-thn-auth-runtime-production','zoolanding-deployer-thn-auth-runtime-production-github-deploy','zoolanding-deployer-thn-auth-runtime-production-cfn-exec','template-thn-runtime-test.yaml'),
 'apiGeneral':('zoolanding-api-proxy-thn-guard-integration','zoolanding-api-proxy','zoolanding-api-proxy','zoolanding-deployer-api-proxy-production-github-deploy','zoolanding-deployer-api-proxy-production-cfn-exec','template.yaml'),
}
BUCKET='zlp-thn-production-releases-765932874577-us-east-1'
API_RUNTIME_ROLE='zlp-thn-auth-runtime-prod-role'
API_RUNTIME_FUNCTION='zlp-thn-auth-runtime-production'
ARN=lambda service,value:f'arn:aws:{service}:{REGION}:{ACCOUNT}:{value}'

def function_role_names(native,names):
    result=set()
    for item in native['Resources'].values():
        if item['Type']!='AWS::Lambda::Function':continue
        role=item.get('Properties',{}).get('Role')
        if isinstance(role,dict) and set(role)=={'Fn::GetAtt'}:
            logical,attribute=role['Fn::GetAtt']
            require(attribute=='Arn' and logical in names,'bootstrap_function_role_unresolved')
            result.add(names[logical])
        else:
            prefix=f'arn:aws:iam::{ACCOUNT}:role/'
            require(isinstance(role,str) and role.startswith(prefix) and
                    re.fullmatch(r'[A-Za-z0-9+=,.@_-]{1,64}',role[len(prefix):]),
                    'bootstrap_function_role_unresolved')
            result.add(role[len(prefix):])
    return sorted(result)

def candidate(workspace,group):
    checkout,_,stack,_,_,source=GROUPS[group]
    code="""import os,json,yaml;from pathlib import Path
from tools.prepare_thn_production_template import prepare_template
from samtranslator.translator.transform import transform
source=yaml.safe_load(Path(SOURCE).read_text());candidate=prepare_template(source)
if GENERAL:
 from tools.prepare_thn_production_template import prepare_general_template
 candidate=prepare_general_template(source)
params={name:prop.get('Default','synthetic') for name,prop in candidate.get('Parameters',{}).items()}
for name,prop in candidate.get('Parameters',{}).items():
 if name.startswith(('EnableThn','ProvisionThn')):params[name]='true'
 if name=='EnableThnAuthRuntimeV2' and GENERAL:params[name]='false'
 if name in ('EnvironmentName','AuthRuntimeEnvironment'):params[name]='prod'
 if name=='CognitoUserPoolArns':params[name]=['arn:aws:cognito-idp:us-east-1:765932874577:userpool/us-east-1_synthetic']
 if prop.get('Type')=='CommaDelimitedList' and not isinstance(params[name],list):params[name]=str(params[name]).split(',')
for resource in candidate['Resources'].values():
 if resource['Type']=='AWS::Serverless::Function':resource['Properties']['CodeUri']={'Bucket':BUCKET,'Key':'thn/production/synthetic.zip','Version':'synthetic-version'}
os.environ['AWS_DEFAULT_REGION']='us-east-1'
native=transform(candidate,params,{'AWSLambdaBasicExecutionRole':'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'})
print(json.dumps({'candidate':candidate,'native':native,'params':params},default=str))
""".replace('SOURCE',repr(source)).replace('GENERAL',str(group=='apiGeneral')).replace('BUCKET',repr(BUCKET))
    # General source must not enter the private-only generator first.
    if group=='apiGeneral':code=code.replace('candidate=prepare_template(source)','candidate=source')
    value=subprocess.run([sys.executable,'-c',code],cwd=workspace/checkout,text=True,capture_output=True,check=True)
    return json.loads(value.stdout)

def compile_manifest(workspace,evidence):
    from tools.thn_production_native_permissions import selected_actions
    require(evidence.get('callerAccount')==ACCOUNT)
    schemas=evidence['backendNativeSchemas'];resources={};proof=[];baselines={};candidate_hashes={};planned=[]
    def statement(actions,targets,condition=None):
        value={'Effect':'Allow','Action':sorted(set(actions)),'Resource':sorted(set(targets))}
        if condition:value['Condition']=condition
        return value
    def resolve(value,params,stack):
        variables={'AWS::AccountId':ACCOUNT,'AWS::Region':REGION,'AWS::Partition':'aws','AWS::StackName':stack,**params,**names}
        if isinstance(value,str):return value
        if isinstance(value,dict) and set(value)=={'Ref'}:return str(variables.get(value['Ref'],''))
        if isinstance(value,dict) and set(value)=={'Fn::Sub'}:
            expr=value['Fn::Sub']
            if isinstance(expr,list):
                variables.update({k:resolve(v,params,stack) for k,v in expr[1].items()});expr=expr[0]
            return re.sub(r'\$\{([^}]+)\}',lambda m:str(variables.get(m[1],'')),expr)
        return ''
    for group,(checkout,repo,stack,deploy,execution,source) in GROUPS.items():
        prefix=group[0].upper()+group[1:];value=candidate(workspace,group);native=value['native'];params=value['params']
        actual={r['LogicalResourceId']:r for r in evidence.get('backendResourceIdentities',{}).get(stack,{}).get('identities',[])}
        names={};requirements=[]
        for logical,item in native['Resources'].items():
            kind=item['Type'];require(kind in schemas and schemas[kind]['status']=='present','bootstrap_native_schema_missing')
            fields=item.get('Properties',{});name=''
            for field in ('FunctionName','RoleName','TableName','BucketName','LogGroupName','TopicName','AlarmName','Name'):
                if field in fields:name=resolve(fields[field],params,stack);break
            if logical in actual:name=actual[logical]['PhysicalResourceId']
            if not name:name=f'{stack}-{logical}-*'
            names[logical]=name
            handlers={k:{'permissions':v} for k,v in schemas[kind]['handlerPermissions'].items()}
            changes=[{'Action':action,'LogicalResourceId':logical,'ResourceType':kind} for action in ('Add','Modify') if {'Add':'create','Modify':'update'}[action] in handlers]
            actions=selected_actions(kind,handlers,changes,native)
            requirements.append({'logicalId':logical,'resourceType':kind,'nameOrApprovedGeneratedPrefix':name,'identityStatus':'existing' if logical in actual else 'planned','actions':sorted(actions),'providerSchemaSha256':schemas[kind]['schemaSha256']})
        candidate_hashes[group]={'preparedSourceSha256':sha(value['candidate']),'nativeProjectionSha256':sha(native)}
        stack_arn=ARN('cloudformation','stack/'+stack+'/*');exec_arn=f'arn:aws:iam::{ACCOUNT}:role/{execution}';deploy_arn=f'arn:aws:iam::{ACCOUNT}:role/{deploy}'
        trusted=evidence['backendRoles'].get(deploy,{})
        if trusted.get('status')=='present':
            policy=evidence['backendRolePolicies'][deploy]
            baselines[deploy]={'roleId':trusted['roleId'],'trustSha256':trusted['trustSha256'],'policySetSha256':policy['sha256'],'policySha256':policy['sha256'],'policies':policy['policies']}
        else:
            require(trusted.get('status')=='unavailable','bootstrap_role_baseline_ambiguous')
            resources[prefix+'GithubDeployRole']={'Type':'AWS::IAM::Role','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{'RoleName':deploy,'MaxSessionDuration':3600,'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'sts:AssumeRoleWithWebIdentity','Principal':{'Federated':f'arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com'},'Condition':{'StringEquals':{'token.actions.githubusercontent.com:aud':'sts.amazonaws.com','token.actions.githubusercontent.com:sub':f'repo:LynxPardelle/{repo}:environment:production'}}}]}}}
        caller=[]
        def caller_grant(actions,targets,context=None):
            caller.append(statement(actions,targets,context));proof.append({'group':group,'principalArn':deploy_arn,'actions':sorted(actions),'resources':targets,'condition':context or {}})
        caller_grant(['cloudformation:CreateChangeSet','cloudformation:DescribeChangeSet','cloudformation:ExecuteChangeSet','cloudformation:DeleteChangeSet','cloudformation:GetTemplate','cloudformation:DescribeStacks','cloudformation:ListStackResources','cloudformation:UpdateTerminationProtection'],[stack_arn,ARN('cloudformation','changeSet/thn-production-'+('api' if group=='apiGeneral' else group)+'-*/*')])
        caller_grant(['cloudformation:DescribeType'],['*'])
        caller_grant(['cloudformation:DescribeStacks','cloudformation:GetTemplate','cloudformation:ListStackResources'],[ARN('cloudformation','stack/'+s+'/*') for s in ('zoolanding-auth-admin-prod','zoolanding-content-hub-prod','zoolanding-image-upload')])
        caller_grant(['iam:GetRole','iam:ListRolePolicies','iam:ListAttachedRolePolicies','iam:GetRolePolicy'],[deploy_arn,exec_arn])
        caller_grant(['iam:GetPolicy','iam:GetPolicyVersion','iam:SimulatePrincipalPolicy','iam:GetContextKeysForPrincipalPolicy'],['*'])
        caller_grant(['iam:PassRole'],[exec_arn],{'StringEquals':{'iam:PassedToService':'cloudformation.amazonaws.com'}})
        caller_grant(['s3:GetBucketVersioning','s3:GetBucketPublicAccessBlock'],['arn:aws:s3:::'+BUCKET])
        caller_grant(['s3:PutObject','s3:GetObject','s3:GetObjectVersion','s3:AbortMultipartUpload','s3:ListMultipartUploadParts'],['arn:aws:s3:::'+BUCKET+'/thn/production/'+('api' if group=='apiGeneral' else group)+'/*'])
        lambda_names=[r['nameOrApprovedGeneratedPrefix'] for r in requirements if r['resourceType']=='AWS::Lambda::Function']
        caller_grant(['lambda:GetFunction','lambda:GetFunctionConfiguration'],[ARN('lambda','function:'+name) for name in lambda_names])
        if group!='apiGeneral':
            resources[prefix+'VerifiedOwnerMetadataPolicy']={'Type':'AWS::IAM::Policy','Condition':'HasVerifiedProductionOwnerPool','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{'PolicyName':'ThnVerifiedProductionOwnerMetadataV1','Roles':[{'Ref':prefix+'GithubDeployRole'} if prefix+'GithubDeployRole' in resources else deploy],'PolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':['cognito-idp:DescribeUserPool','cognito-idp:GetUserPoolMfaConfig'],'Resource':{'Ref':'ThnProductionOwnerPoolArn'}}]}}}
        caller_grant(['dynamodb:GetItem'],[ARN('dynamodb','table/zoolanding-content-hub-prod-ServiceBindingRegistryV2')],{'ForAllValues:StringEquals':{'dynamodb:LeadingKeys':['SERVICE_BINDING#production#thn-journal-production-v2']}})
        resources[prefix+'GithubReleasePolicy']={'Type':'AWS::IAM::Policy','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{'PolicyName':'ThnRetainedProductionReleaseV1','Roles':[{'Ref':prefix+'GithubDeployRole'} if prefix+'GithubDeployRole' in resources else deploy],'PolicyDocument':{'Version':'2012-10-17','Statement':caller}}}
        execution_statements=[]
        iam_names=[r['nameOrApprovedGeneratedPrefix'] for r in requirements if r['resourceType']=='AWS::IAM::Role']
        lambda_roles=function_role_names(native,names)
        for row in requirements:
            kind=row['resourceType'];name=row['nameOrApprovedGeneratedPrefix'];targets=[]
            if kind.startswith('AWS::Lambda'):targets=[ARN('lambda','function:'+n+suffix) for n in lambda_names for suffix in ('',':*')]
            elif kind=='AWS::IAM::Role':targets=[f'arn:aws:iam::{ACCOUNT}:role/'+name]
            elif kind=='AWS::IAM::Policy':
                roles=native['Resources'][row['logicalId']]['Properties']['Roles']
                role_names=[names[v['Ref']] if isinstance(v,dict) and v.get('Ref') in names else resolve(v,params,stack) for v in roles]
                require(all(role_names),'bootstrap_inline_policy_role_scope_missing')
                targets=[f'arn:aws:iam::{ACCOUNT}:role/'+n for n in role_names]
            elif kind.startswith('AWS::DynamoDB'):targets=[ARN('dynamodb','table/'+name)]
            elif kind.startswith('AWS::S3'):targets=['arn:aws:s3:::'+n for r in requirements if r['resourceType']=='AWS::S3::Bucket' for n in [r['nameOrApprovedGeneratedPrefix']]]
            elif kind.startswith('AWS::Logs'):
                require(any(name.startswith(prefix) and len(name)>len(prefix) for prefix in ('/aws/lambda/','/aws/apigateway/')),'bootstrap_log_identity_unresolved:'+group+':'+row['logicalId']+':'+name)
                targets=[ARN('logs','log-group:'+name+':*')]
            elif kind.startswith('AWS::Cognito'):targets=[ARN('cognito-idp','userpool/*')]
            elif kind.startswith('AWS::ApiGateway'):
                ids=[r['nameOrApprovedGeneratedPrefix'] for r in requirements if r['resourceType'] in {'AWS::ApiGateway::RestApi','AWS::ApiGatewayV2::Api'} and r['identityStatus']=='existing']
                family='apis' if 'V2' in kind else 'restapis'
                targets=[f'arn:aws:apigateway:{REGION}::/{family}',*[f'arn:aws:apigateway:{REGION}::/{family}/{i}/*' for i in ids],*[f'arn:aws:apigateway:{REGION}::/{family}/{i}' for i in ids]]
                if any(r['resourceType'] in {'AWS::ApiGateway::RestApi','AWS::ApiGatewayV2::Api'} and r['identityStatus']=='planned' for r in requirements):targets.append(f'arn:aws:apigateway:{REGION}::/{family}/*')
            elif kind=='AWS::CloudWatch::Alarm':targets=[ARN('cloudwatch','alarm:'+name)]
            elif kind.startswith('AWS::SNS'):targets=[(r['nameOrApprovedGeneratedPrefix'] if r['nameOrApprovedGeneratedPrefix'].startswith('arn:aws:sns:') else ARN('sns',r['nameOrApprovedGeneratedPrefix'])) for r in requirements if r['resourceType']=='AWS::SNS::Topic']
            elif kind=='AWS::Events::Rule':targets=[ARN('events','rule/'+name)]
            require(targets,'bootstrap_resource_scope_unavailable')
            for action in row['actions']:
                scope=targets;condition={'StringEquals':{'aws:RequestedRegion':REGION}}
                if action.startswith('cloudformation:'):scope=[stack_arn]
                elif action=='iam:PassRole':scope=[f'arn:aws:iam::{ACCOUNT}:role/'+n for n in lambda_roles];condition={'StringEquals':{'iam:PassedToService':'lambda.amazonaws.com'}}
                elif action.lower() in {'s3:getobject','s3:getobjectversion'}:scope=['arn:aws:s3:::'+BUCKET+'/thn/production/'+('api' if group=='apiGeneral' else group)+'/*']
                elif action=='cognito-idp:CreateUserPool':scope=['*']
                elif action.startswith('logs:Describe'):scope=['*']
                execution_statements.append(statement([action],scope,condition))
                proof.append({'group':group,'principalArn':exec_arn,'logicalId':row['logicalId'],'resourceType':kind,'actions':[action],'resources':scope,'condition':condition,'providerSchemaSha256':row['providerSchemaSha256']})
        unique={}
        for item in execution_statements:
            key=sha({k:v for k,v in item.items() if k!='Action'})
            if key not in unique:unique[key]=item
            else:unique[key]['Action']=sorted(set(unique[key]['Action'])|set(item['Action']))
        resources[prefix+'CfnExecutionRole']={'Type':'AWS::IAM::Role','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{'RoleName':execution,'MaxSessionDuration':3600,'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'Service':'cloudformation.amazonaws.com'}}]},'Policies':[{'PolicyName':'OperateExactReviewedBackendStack','PolicyDocument':{'Version':'2012-10-17','Statement':list(unique.values())}}]}}
        chunks=[];chunk=[]
        for item in unique.values():
            proposed=chunk+[item]
            if len(json.dumps({'Version':'2012-10-17','Statement':proposed},separators=(',',':')))>5800:
                require(chunk,'bootstrap_single_statement_exceeds_policy_limit');chunks.append(chunk);chunk=[item]
            else:chunk=proposed
        if chunk:chunks.append(chunk)
        require(len(chunks)<=10,'bootstrap_role_managed_policy_limit')
        refs=[]
        for index,statements in enumerate(chunks):
            logical=prefix+'CfnNativePolicy'+str(index)
            resources[logical]={'Type':'AWS::IAM::ManagedPolicy','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{'ManagedPolicyName':'ThnProduction'+prefix+'Native'+str(index),'PolicyDocument':{'Version':'2012-10-17','Statement':statements}}}
            refs.append({'Ref':logical})
        properties=resources[prefix+'CfnExecutionRole']['Properties'];del properties['Policies'];properties['ManagedPolicyArns']=refs
        planned.append({'group':group,'repository':repo,'stackName':stack,'deployRoleArn':deploy_arn,'executionRoleArn':exec_arn,'resourceRequirements':requirements})
    resources['ApiRuntimeRole']={
        'Type':'AWS::IAM::Role','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain',
        'Properties':{
            'RoleName':API_RUNTIME_ROLE,'MaxSessionDuration':3600,
            'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[
                {'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'Service':'lambda.amazonaws.com'}}]},
            'Policies':[{'PolicyName':'ThnExactProductionRegistryRuntimeRead',
                'PolicyDocument':{'Version':'2012-10-17','Statement':[
                    statement(['dynamodb:GetItem'],[ARN('dynamodb','table/zoolanding-content-hub-prod-ServiceBindingRegistryV2')],
                        {'ForAllValues:StringEquals':{'dynamodb:LeadingKeys':['SERVICE_BINDING#production#thn-journal-production-v2']},
                         'Null':{'dynamodb:LeadingKeys':'false'}}),
                    statement(['logs:CreateLogStream','logs:PutLogEvents'],
                        [ARN('logs','log-group:/aws/lambda/'+API_RUNTIME_FUNCTION+':*')])
                ]}}]}}
    merged={}
    for row in proof:
        key=sha({k:v for k,v in row.items() if k!='logicalId'})
        if key not in merged:merged[key]={k:v for k,v in row.items() if k!='logicalId'}
        if 'logicalId' in row:merged[key].setdefault('logicalIds',[]).append(row['logicalId'])
    proof=list(merged.values())
    manifest={'schemaVersion':1,'environment':'production','account':ACCOUNT,'region':REGION,'bootstrapStackName':'ZoolandingProduction-Zoolandingpage-production-ThnDeploymentIdentities','template':{'AWSTemplateFormatVersion':'2010-09-09','Parameters':{'ThnProductionOwnerPoolArn':{'Type':'String','Default':'BLOCKED','AllowedPattern':'^(BLOCKED|arn:aws:cognito-idp:us-east-1:765932874577:userpool/us-east-1_[A-Za-z0-9]+)$'}},'Conditions':{'HasVerifiedProductionOwnerPool':{'Fn::Not':[{'Fn::Equals':[{'Ref':'ThnProductionOwnerPoolArn'},'BLOCKED']}]}},'Resources':resources},'externalRolePolicyBaselines':baselines,'providerSchemaHashes':{kind:v['schemaSha256'] for kind,v in schemas.items()},'sourceCandidateHashes':candidate_hashes,'proofMatrix':proof,'groups':planned,'packageBucket':BUCKET,'readiness':'planned; effective permission simulations and exact native approval remain required'}
    return manifest

def overlay_api_manifest(base,generated):
    """Carry only the reviewed API identity slice into a later manifest."""
    require(all(base.get(key)==generated.get(key) for key in
                ('schemaVersion','environment','account','region','bootstrapStackName')),
            'bootstrap_api_overlay_identity_changed')
    result=deepcopy(base)
    current=result['template']['Resources'];proposed=generated['template']['Resources']
    api=lambda name:name.startswith('Api') and not name.startswith('ApiGeneral')
    old_api={name for name in current if api(name)}
    new_api={name for name in proposed if api(name)}
    require(old_api<=new_api and 'ApiRuntimeRole' in new_api,
            'bootstrap_api_overlay_resource_changed')
    for name in new_api:current[name]=deepcopy(proposed[name])
    old_groups=[item for item in result['groups'] if item['group']=='api']
    new_groups=[item for item in generated['groups'] if item['group']=='api']
    require(len(old_groups)==len(new_groups)==1,'bootstrap_api_overlay_group_changed')
    result['groups']=[deepcopy(new_groups[0]) if item['group']=='api' else item
                      for item in result['groups']]
    old_proof=result['proofMatrix'];api_rows=[deepcopy(item) for item in
                                               generated['proofMatrix'] if item['group']=='api']
    positions=[index for index,item in enumerate(old_proof) if item['group']=='api']
    require(positions and positions==list(range(positions[0],positions[-1]+1)) and api_rows,
            'bootstrap_api_overlay_proof_changed')
    result['proofMatrix']=old_proof[:positions[0]]+api_rows+old_proof[positions[-1]+1:]
    result['sourceCandidateHashes']['api']=deepcopy(generated['sourceCandidateHashes']['api'])
    return result

def main():
 p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--workspace',type=Path,default=ROOT.parent);p.add_argument('--output',type=Path,default=ROOT/'tools/production/thn-deployment-identities.json');p.add_argument('--base',type=Path);args=p.parse_args()
 value=compile_manifest(args.workspace,json.loads(args.evidence.read_text()))
 if args.base:value=overlay_api_manifest(json.loads(args.base.read_text()),value)
 args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');print(json.dumps({'manifestSha256':sha(value),'resources':len(value['template']['Resources']),'proofs':len(value['proofMatrix'])}))
if __name__=='__main__':main()
