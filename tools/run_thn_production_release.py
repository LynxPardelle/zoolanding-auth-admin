"""Protected production CLI. Exact retained preview; private versioned recovery.

Required deployment/permission selections are provided by a reviewed production
Environment. Missing proposed roles, bindings, proofs or objects fail closed.
"""
from pathlib import Path
import argparse
import json
import os
import subprocess
import sys
import time
from urllib.parse import quote, urlparse
import zipfile
import io
import base64
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools import thn_production_release as release
from tools.thn_production_service import CONFIG

def load_json(value):
    def pairs(items):
        result={}
        for k,v in items:
            release.require(k not in result,'production_duplicate_json_key')
            result[k]=v
        return result
    release.require(isinstance(value,str) and 0<len(value.encode())<=1024*1024)
    return json.loads(value,object_pairs_hook=pairs)

def production_environment():
    """Read the independent GitHub branch fence; AWS cannot evaluate a ref claim."""
    repository=f'LynxPardelle/{CONFIG["repository"]}'
    endpoint=f'repos/{repository}/environments/production'
    def read(url):
        return load_json(subprocess.run(['gh','api',url],text=True,capture_output=True,check=True).stdout)
    environment=read(endpoint)
    rules=read(endpoint+'/deployment-branch-policies?per_page=100&page=1')
    policy=environment.get('deployment_branch_policy')
    release.require(environment.get('name')=='production' and
        environment.get('html_url')==f'https://github.com/{repository}/deployments/activity_log?environments_filter=production' and
        isinstance(policy,dict) and set(policy)=={'custom_branch_policies','protected_branches'} and
        policy['custom_branch_policies'] is True and policy['protected_branches'] is False,
        'production_environment_branch_fence_invalid')
    branches=rules.get('branch_policies')
    release.require(type(rules.get('total_count')) is int and rules['total_count']==1 and
        isinstance(branches,list) and len(branches)==1 and
        branches[0].get('name')=='main' and branches[0].get('type')=='branch',
        'production_environment_branch_fence_invalid')
    return {'repository':repository,'environment':'production','branch':'main',
        'deploymentBranchPolicy':policy,'branchPolicies':branches,
        'protectionRules':environment.get('protection_rules',[])}

def validate_github_trust(trust):
    expected={'Effect':'Allow','Action':'sts:AssumeRoleWithWebIdentity',
        'Principal':{'Federated':f'arn:aws:iam::{release.ACCOUNT}:oidc-provider/token.actions.githubusercontent.com'},
        'Condition':{'StringEquals':{'token.actions.githubusercontent.com:aud':'sts.amazonaws.com',
            'token.actions.githubusercontent.com:sub':f'repo:LynxPardelle/{CONFIG["repository"]}:environment:production'}}}
    release.require(isinstance(trust,dict) and trust.get('Statement')==[expected] and
        set(trust)<= {'Version','Statement'} and trust.get('Version','2012-10-17')=='2012-10-17',
        'production_github_standard_trust_invalid')

def source_selection(source_sha):
    git=lambda *args:subprocess.run(['git',*args],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip()
    release.require(release._sha(source_sha,40) and git('rev-parse','HEAD')==source_sha)
    release.require(git('rev-parse','refs/remotes/origin/main')==source_sha,'production_main_changed')
    latest=subprocess.run(['gh','api',f'repos/LynxPardelle/{CONFIG["repository"]}/git/ref/heads/main','--jq','.object.sha'],
        text=True,capture_output=True,check=True).stdout.strip()
    release.require(latest==source_sha,'production_remote_main_changed')
    release.require(os.environ.get('GITHUB_REPOSITORY')==f'LynxPardelle/{CONFIG["repository"]}' and
        os.environ.get('GITHUB_REF')=='refs/heads/main' and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch')
    subprocess.run(['git','diff','--quiet','HEAD','--'],cwd=ROOT,check=True)
    return {'sourceSha':source_sha,'sourceTree':git('rev-parse','HEAD^{tree}'),
        'productionEnvironment':production_environment(),
        'operationFiles':{name:release.sha((ROOT/name).read_bytes()) for name in
            ('tools/thn_production_release.py','tools/run_thn_production_release.py',
             'tools/thn_production_service.py','tools/prepare_thn_production_template.py',
             '.github/workflows/deploy-thn-production.yml','tools/thn_production_prerequisites.py',
             'tools/thn_production_native_permissions.py')}}

CALLER_ACTIONS=frozenset({'cloudformation:CreateChangeSet','cloudformation:DescribeChangeSet',
    'cloudformation:GetTemplate','cloudformation:DescribeStacks','cloudformation:ListStackResources',
    'cloudformation:ExecuteChangeSet','cloudformation:DeleteChangeSet','cloudformation:UpdateTerminationProtection',
    'cloudformation:DescribeType','iam:GetRole','iam:ListRolePolicies','iam:ListAttachedRolePolicies',
    'iam:GetRolePolicy','iam:GetPolicy','iam:GetPolicyVersion','iam:PassRole',
    'iam:SimulatePrincipalPolicy','iam:GetContextKeysForPrincipalPolicy','s3:GetBucketVersioning',
    's3:GetBucketPublicAccessBlock','s3:AbortMultipartUpload','s3:ListMultipartUploadParts','s3:PutObject','s3:GetObject','s3:GetObjectVersion',
    'lambda:GetFunction','lambda:GetFunctionConfiguration'})

def identity_and_permissions(session,source,purpose,native_changes=None,native_template=None,previous=None):
    release.require(session.region_name==release.REGION)
    identity=session.client('sts').get_caller_identity()
    expected=CONFIG['deployRole']
    release.require(identity.get('Account')==release.ACCOUNT and
        str(identity.get('Arn','')).startswith(f'arn:aws:sts::{release.ACCOUNT}:assumed-role/{expected}/'))
    iam=session.client('iam')
    role=iam.get_role(RoleName=expected)['Role']
    validate_github_trust(role['AssumeRolePolicyDocument'])
    execution=iam.get_role(RoleName=CONFIG['executionRole'])['Role']
    trust=execution['AssumeRolePolicyDocument']['Statement']
    release.require(len(trust)==1 and trust[0]['Effect']=='Allow' and
        trust[0]['Principal']=={'Service':'cloudformation.amazonaws.com'} and trust[0]['Action']=='sts:AssumeRole')
    plan=load_json(os.environ.get('THN_PRODUCTION_PERMISSION_PLAN_JSON',''))
    release.require(set(plan)=={'schemaVersion','environment','service','purpose','sourceSha','requests'})
    release.require(type(plan['schemaVersion']) is int and plan['schemaVersion']==1 and
        plan['environment']=='production' and plan['service']==CONFIG['service'] and
        plan['sourceSha']==source['sourceSha'] and plan['purpose']==purpose)
    release.require(isinstance(plan['requests'],list) and plan['requests'],'production_effective_permission_plan_missing')
    if purpose=='activate':release.require({'cognito-idp:DescribeUserPool','cognito-idp:GetUserPoolMfaConfig','dynamodb:GetItem'}<=set().union(*(set(r.get('actions',[])) for r in plan['requests'] if r.get('principalArn')==role['Arn'])),'production_verified_metadata_permissions_missing')
    caller_actions=set().union(*(set(r.get('actions',[])) for r in plan['requests'] if r.get('principalArn')==role['Arn']))
    release.require(CALLER_ACTIONS<=caller_actions,'production_caller_permission_coverage_incomplete')
    schemas=[];required_execution=set()
    from tools.thn_production_native_permissions import selected_actions
    by_type={}
    for item in native_changes or []:
        change=item['ResourceChange'];by_type.setdefault(change['ResourceType'],[]).append(change)
    for kind in sorted(by_type):
        metadata=session.client('cloudformation').describe_type(Type='RESOURCE',TypeName=kind)
        schema=load_json(metadata['Schema'])
        permissions=selected_actions(kind,schema['handlers'],by_type[kind],native_template,previous)
        release.require(permissions,'production_native_handler_permissions_unavailable')
        required_execution.update(permissions)
        schemas.append({'resourceType':kind,'schemaSha256':release.sha(schema),'handlerPermissions':sorted(permissions)})
    execution_actions=set().union(*(set(r.get('actions',[])) for r in plan['requests'] if r.get('principalArn')==execution['Arn']))
    release.require(required_execution<=execution_actions and execution_actions,'production_execution_permission_coverage_incomplete')
    proofs=[]
    allowed={role['Arn'],execution['Arn']}
    for request in plan['requests']:
        release.require(set(request)=={'principalArn','actions','resources','context'})
        release.require(request['principalArn'] in allowed and isinstance(request['actions'],list) and
            request['actions'] and isinstance(request['resources'],list) and request['resources'])
        release.require(all(isinstance(a,str) and '*' not in a and ':' in a for a in request['actions']))
        # Only the concrete action/resource simulation determines relevant
        # missing context. Whole-policy context keys include unrelated statements.
        # IAM action names are case insensitive. The live simulator rejects
        # some mixed-case spellings even under an otherwise identical policy.
        # Preserve the reviewed request; normalize only the simulation input.
        kwargs={'PolicySourceArn':request['principalArn'],'ActionNames':[a.lower() for a in request['actions']],
            'ResourceArns':request['resources'],'ContextEntries':request['context']}
        result=iam.simulate_principal_policy(**kwargs)
        evaluations=result.get('EvaluationResults',[])
        release.require(result.get('IsTruncated') is not True and {e['EvalActionName'].lower() for e in evaluations}=={a.lower() for a in request['actions']},
            'production_iam_simulation_incomplete')
        for evaluation in evaluations:
            release.require(evaluation.get('EvalDecision')=='allowed' and not evaluation.get('MissingContextValues'),
                'production_effective_permission_denied')
            release.require(all(item.get('EvalResourceDecision')=='allowed' and not item.get('MissingContextValues') for item in evaluation.get('ResourceSpecificResults',[])))
        for action in kwargs['ActionNames']:
            covered=[]
            for evaluation in evaluations:
                if evaluation['EvalActionName'].lower()!=action:continue
                nested=evaluation.get('ResourceSpecificResults',[])
                if nested:covered.extend(item.get('EvalResourceName') for item in nested)
                else:covered.append(evaluation.get('EvalResourceName'))
            release.require(sorted(covered,key=str)==sorted(request['resources']),
                'production_iam_simulation_resource_coverage_incomplete')
        proofs.append({'request':request,'evaluation':release.stable_simulation_evaluations(evaluations)})
    # Full policy documents stay in memory, are fingerprinted and never emitted.
    def policies(name):
        values=[]
        for page in iam.get_paginator('list_role_policies').paginate(RoleName=name):
            for policy in page['PolicyNames']:
                values.append(iam.get_role_policy(RoleName=name,PolicyName=policy)['PolicyDocument'])
        for page in iam.get_paginator('list_attached_role_policies').paginate(RoleName=name):
            for policy in page['AttachedPolicies']:
                metadata=iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']
                values.append(iam.get_policy_version(PolicyArn=policy['PolicyArn'],VersionId=metadata['DefaultVersionId'])['PolicyVersion']['Document'])
        return sorted(values,key=release.canonical)
    role.pop('RoleLastUsed',None);execution.pop('RoleLastUsed',None)
    fingerprints={'callerRole':role,'executionRole':execution,'callerPolicies':policies(expected),
        'executionPolicies':policies(CONFIG['executionRole'])}
    return fingerprints,{'requests':proofs,'nativeSchemas':schemas}

def captured_baseline(session):
    def absent():
        value={'absent':True,'stackName':CONFIG['stack'],'terminationProtection':True,'processed':{'Resources':{}},'original':{'Resources':{}},'parameters':[]}
        if os.environ.get('THN_PRODUCTION_SELECTED_PURPOSE')=='activate':
            from tools.thn_production_prerequisites import capture
            value['prerequisites']=capture(session,load_json(os.environ.get('THN_PRODUCTION_PREREQUISITES_JSON','')),CONFIG['service'],os.environ['THN_PRODUCTION_SELECTED_SOURCE'])
        return value
    cf=session.client('cloudformation')
    if CONFIG['service']=='api':
        try:
            staged=cf.describe_stacks(StackName=CONFIG['stack'])['Stacks'][0]
            if staged.get('StackStatus')=='REVIEW_IN_PROGRESS':
                rows=cf.list_stack_resources(StackName=CONFIG['stack']).get('StackResourceSummaries',[])
                release.require(not rows and staged.get('EnableTerminationProtection') is True)
                return absent()
        except Exception as error:
            if getattr(error,'response',{}).get('Error',{}).get('Code')!='ValidationError':raise
    try:
        baseline=release.snapshot(cf,CONFIG['stack'])
    except Exception as error:
        code=getattr(error,'response',{}).get('Error',{}).get('Code')
        if not(CONFIG['service']=='api' and code=='ValidationError' and 'does not exist' in str(error)):
            raise
        return absent()
    release.require(baseline['terminationProtection'] is True,'production_termination_protection_missing')
    fingerprints=[]
    client=session.client('lambda')
    for resource in baseline['resources']:
        if resource.get('ResourceType')=='AWS::Lambda::Function':
            config=client.get_function_configuration(FunctionName=resource['PhysicalResourceId'])
            config.pop('ResponseMetadata',None)
            fingerprints.append({'logicalId':resource['LogicalResourceId'],'physicalId':resource['PhysicalResourceId'],
                'configurationSha256':release.sha(config),'codeSha256':config['CodeSha256']})
    baseline['lambdaFingerprints']=fingerprints
    if os.environ.get('THN_PRODUCTION_SELECTED_PURPOSE')=='activate':
        from tools.thn_production_prerequisites import capture
        baseline['prerequisites']=capture(session,load_json(os.environ.get('THN_PRODUCTION_PREREQUISITES_JSON','')),CONFIG['service'],os.environ['THN_PRODUCTION_SELECTED_SOURCE'])
    return baseline

def sealed_packages(session,template):
    s3=session.client('s3');manifest=[]
    for logical,item in template['Resources'].items():
        if item['Type']!='AWS::Serverless::Function': continue
        code=item['Properties']['CodeUri']
        if isinstance(code,str):
            uri=urlparse(code);release.require(uri.scheme=='s3')
            bucket,key=uri.netloc,uri.path.lstrip('/')
        else: bucket,key=code['Bucket'],code['Key']
        release.require(bucket==CONFIG['bucket'] and key.startswith('thn/production/'),
            'production_package_scope_invalid')
        version=s3.head_object(Bucket=bucket,Key=key)['VersionId']
        release.require(version not in {'','null'})
        body=s3.get_object(Bucket=bucket,Key=key,VersionId=version)['Body'].read()
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            names=set(archive.namelist())
            release.require(all(not name.startswith('/') and '..' not in Path(name).parts for name in names))
            if logical.startswith(('Thn','ServiceBinding')):
                release.require('thn_environment_profile.py' in names)
                expected=(ROOT/'thn_environment_profile.py').read_bytes()
                release.require(archive.read('thn_environment_profile.py')==expected)
                if logical=='ThnProductionOwnerOperatorV2Function':
                    release.require('auth_admin_production_owner_operator_v2.py' in names and
                        not({'auth_admin_owner_operator_v2.py','auth_admin_qa_operator_v2.py','tools/provision_thn_owner.py','tools/provision_thn_qa.py'}&names))
            if CONFIG['service']=='api':
                if CONFIG.get('generalStack')==CONFIG['stack']:
                    from tools.build_production_legacy_artifact import FILES
                    from tools.build_thn_auth_runtime_v2_artifact import ALLOWED_FILES
                    expected_sources=set(ALLOWED_FILES if logical=='ThnAuthRuntimeV2Function' else FILES)
                    release.require({name for name in names if (ROOT/name).is_file()}==expected_sources)
                else:
                    from tools.build_thn_auth_runtime_v2_artifact import ALLOWED_FILES
                    expected_sources=set(ALLOWED_FILES)
                    release.require(names==expected_sources)
            else:
                from tools.build_lambda_artifact import SOURCE_ALLOWLIST
                if CONFIG["service"] == "auth":
                    from tools.build_lambda_artifact import PRODUCTION_SOURCE_ALLOWLIST
                    SOURCE_ALLOWLIST = PRODUCTION_SOURCE_ALLOWLIST
                expected_sources=set(SOURCE_ALLOWLIST[logical])
                project_sources={name for name in names if (ROOT/name).is_file()}
                release.require(project_sources==expected_sources,'production_zip_source_inventory_mismatch')
            release.require(all(archive.read(name)==(ROOT/name).read_bytes() for name in expected_sources),
                'production_zip_source_bytes_mismatch')
        item['Properties']['CodeUri']={'Bucket':bucket,'Key':key,'Version':version}
        manifest.append({'bucket':bucket,'key':key,'versionId':version,'sha256':release.sha(body)})
    release.require(manifest,'production_packages_missing')
    return sorted(manifest,key=release.canonical)

def candidate_for_scope(candidate,baseline,purpose):
    """General review includes full incoming source; private stages preserve v1."""
    old=release.parse_template(baseline['original'])
    if purpose in {'state','activate'} and not baseline.get('absent'):
        for logical,item in old['Resources'].items():
            if not logical.startswith(('Thn','ServiceBinding')) and logical!='ContentHubApi':
                candidate['Resources'][logical]=item
        for name,item in old.get('Parameters',{}).items():
            if not name.startswith(('Thn','ServiceBinding','ProvisionThn','EnableThn')) and name!='EnvironmentName':
                candidate['Parameters'][name]=item
    return candidate

def review(session,args,source,identity,permissions):
    cf=session.client('cloudformation');s3=session.client('s3')
    baseline=captured_baseline(session)
    release.require(not baseline.get('absent') or args.purpose=='activate',
        'production_dedicated_runtime_requires_verified_activation')
    packaged=None
    if args.purpose=='recover':
        prior=load_json(Path(args.recovery_record).read_text())
        release.verify_review_record(prior,approved_digest=prior['digest'],now=min(int(time.time()),prior['expiresAt']-1),
            service=CONFIG['service'],source_sha=prior['sourceSha'])
        release.require(prior['recoveryCoordinates'],'production_original_bytes_unavailable')
        # Exact previous Original template, not a rebuild of historical code.
        packaged=release.parse_template(release.verify_object(s3,prior['recoveryCoordinates'][0]).decode())
        packages=prior['recoveryCoordinates'][1:]
        for coordinate in packages: release.verify_object(s3,coordinate)
    else:
        packaged=release.parse_template(Path(args.template).read_text())
        packages=sealed_packages(session,packaged)
        packaged=candidate_for_scope(packaged,baseline,args.purpose)
    overrides=load_json(os.environ.get('THN_PRODUCTION_PARAMETERS_JSON','{}'))
    parameters=release.select_parameters(packaged.get('Parameters',{}),baseline['parameters'],overrides,purpose=args.purpose)
    prefix=f'thn/production/{CONFIG["service"]}/{source["sourceSha"]}/{os.environ["GITHUB_RUN_ID"]}/{os.environ["GITHUB_RUN_ATTEMPT"]}/'
    recovery=[]
    if not baseline.get('absent'):
        original=release.parse_template(baseline['original'])
        historical=[]
        functions={r['LogicalResourceId']:r for r in baseline['resources'] if r.get('ResourceType')=='AWS::Lambda::Function'}
        for logical,item in original['Resources'].items():
            if item['Type'] not in {'AWS::Serverless::Function','AWS::Lambda::Function'}:continue
            release.require(logical in functions,'production_original_function_unresolved')
            old=session.client('lambda').get_function(FunctionName=functions[logical]['PhysicalResourceId'])
            with urllib.request.urlopen(old['Code']['Location'],timeout=30) as response:
                body=response.read()
            release.require(base64.b64encode(__import__('hashlib').sha256(body).digest()).decode()==old['Configuration']['CodeSha256'],
                'production_original_code_hash_mismatch')
            coordinate=release.seal_object(s3,CONFIG['bucket'],prefix+'recovery/'+logical+'.zip',body)
            historical.append(coordinate)
            code={'Bucket':coordinate['bucket'],'Key':coordinate['key'],'Version':coordinate['versionId']}
            if item['Type']=='AWS::Serverless::Function':item['Properties']['CodeUri']=code
            else:item['Properties']['Code']={'S3Bucket':code['Bucket'],'S3Key':code['Key'],'S3ObjectVersion':code['Version']}
        recovery.append(release.seal_object(s3,CONFIG['bucket'],prefix+'previous-original.json',release.canonical(original)))
        recovery.extend(historical)
    template=release.seal_object(s3,CONFIG['bucket'],prefix+'candidate-original.json',release.canonical(packaged))
    url=f'https://{CONFIG["bucket"]}.s3.{release.REGION}.amazonaws.com/{quote(template["key"])}?versionId={quote(template["versionId"])}'
    name=f'thn-production-{CONFIG["service"]}-{args.purpose}-{os.environ["GITHUB_RUN_ID"]}-{os.environ["GITHUB_RUN_ATTEMPT"]}'
    release.require(source_selection(source['sourceSha'])==source,'production_source_changed_before_review')
    response=cf.create_change_set(StackName=CONFIG['stack'],ChangeSetName=name,
        ChangeSetType='CREATE' if baseline.get('absent') else 'UPDATE',TemplateURL=url,
        Parameters=parameters,Capabilities=['CAPABILITY_NAMED_IAM','CAPABILITY_AUTO_EXPAND'],
        RoleARN=f'arn:aws:iam::{release.ACCOUNT}:role/{CONFIG["executionRole"]}',
        Tags=baseline.get('tags',[{'Key':'thn:environment','Value':'production'},{'Key':'thn:service','Value':CONFIG['service']}]))
    arn=response['Id']
    cf.get_waiter('change_set_create_complete').wait(ChangeSetName=arn)
    if baseline.get('absent'):
        # A CREATE preview leaves an empty REVIEW_IN_PROGRESS stack. Protect it
        # before recording the baseline; no resources/routes are executed here.
        cf.update_termination_protection(EnableTerminationProtection=True,StackName=CONFIG['stack'])
        baseline=captured_baseline(session)
    preview=release.describe_preview(cf,arn)
    original=release.parse_template(cf.get_template(ChangeSetName=arn,TemplateStage='Original')['TemplateBody'])
    processed=release.parse_template(cf.get_template(ChangeSetName=arn,TemplateStage='Processed')['TemplateBody'])
    release.review_inventory(preview['Changes'],release.parse_template(baseline['processed']),processed,scope=args.purpose)
    # Native provider handler schemas supply their actual required actions.
    # A guessed action list is insufficient even when caller simulation passes.
    identity,permissions=identity_and_permissions(session,source,args.purpose,
        preview['Changes'],processed,release.parse_template(baseline['processed']))
    record=release.make_review_record(service=CONFIG['service'],purpose=args.purpose,source_sha=source['sourceSha'],
        stack_id=preview['StackId'],change_set_arn=arn,created_at=int(time.time()),baseline=baseline,
        original=original,processed=processed,parameters=preview.get('Parameters',[]),packages=packages,
        changes=preview['Changes'],recovery=recovery,permissions=permissions,identity=identity,source_package=source)
    Path(args.record).write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    # Public identities, inventory and digests only. No template/parameter/config dump.
    print(json.dumps({'digest':record['digest'],'changeSetArn':arn,'changes':record['changes'],'expiresAt':record['expiresAt']}))

def fresh_execute_authority(session,record,source,purpose,preview,processed):
    release.require(source_selection(source['sourceSha'])==source,'production_source_changed_before_execute')
    baseline=captured_baseline(session)
    release.require(release.sha(baseline)==record['baselineSha256'],'production_baseline_changed_before_execute')
    identity,permissions=identity_and_permissions(session,source,purpose,preview['Changes'],processed,
        release.parse_template(baseline['processed']))
    release.require(release.sha(identity)==record['identitySha256'] and
        release.sha(permissions)==record['permissionSha256'],'production_permissions_changed_before_execute')
    release.require(release.sha(source)==record['sourcePackageSha256'],'production_source_package_changed')


def main(argv=None):
    global CONFIG
    p=argparse.ArgumentParser()
    p.add_argument('operation',choices=('validate','preflight','review','execute','cleanup'))
    p.add_argument('--source-sha',required=True)
    p.add_argument('--purpose',choices=sorted(release.PURPOSES),required=True)
    p.add_argument('--scope',choices=('private','general'),default='private')
    p.add_argument('--template',default='packaged-production.json')
    p.add_argument('--record',default='production-review.json')
    p.add_argument('--approved-digest',default='')
    p.add_argument('--recovery-record',default='previous-production-review.json')
    args=p.parse_args(argv)
    try:
        if CONFIG['service']=='api' and args.purpose=='general':release.require(args.scope=='general','production_api_general_scope_required')
        if args.scope=='general':release.require(CONFIG['service']=='api' and args.purpose in {'general','recover'},'production_scope_invalid')
        if args.scope=='general' and 'generalStack' in CONFIG:
            CONFIG={**CONFIG,'stack':CONFIG['generalStack'],'deployRole':CONFIG['generalDeployRole'],
                'executionRole':CONFIG['generalExecutionRole']}
        source=source_selection(args.source_sha)
        os.environ['THN_PRODUCTION_SELECTED_PURPOSE']=args.purpose
        os.environ['THN_PRODUCTION_SELECTED_SOURCE']=args.source_sha
        if args.operation=='validate':
            release.require(not args.approved_digest or release._sha(args.approved_digest))
            return 0
        release.require(os.environ.get('AWS_ROLE_ARN')==f'arn:aws:iam::{release.ACCOUNT}:role/{CONFIG["deployRole"]}')
        import boto3
        session=boto3.Session(region_name=release.REGION)
        identity,permissions=identity_and_permissions(session,source,args.purpose)
        if args.operation=='preflight':
            captured_baseline(session)
            s3=session.client('s3')
            release.require(s3.get_bucket_versioning(Bucket=CONFIG['bucket']).get('Status')=='Enabled')
            block=s3.get_public_access_block(Bucket=CONFIG['bucket'])['PublicAccessBlockConfiguration']
            release.require(all(block.get(k) is True for k in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')))
            return 0
        if args.operation=='review': review(session,args,source,identity,permissions)
        else:
            record=load_json(Path(args.record).read_text())
            release.require(record['purpose']==args.purpose and record['stackId'].startswith(f'arn:aws:cloudformation:{release.REGION}:{release.ACCOUNT}:stack/{CONFIG["stack"]}/'),'production_record_stack_scope_invalid')
            if args.operation=='cleanup':
                release.cleanup_retained(session.client('cloudformation'),record,service=CONFIG['service'],source_sha=record['sourceSha'])
            else:
                baseline=captured_baseline(session)
                preview=release.describe_preview(session.client('cloudformation'),record['changeSetArn'])
                identity,permissions=identity_and_permissions(session,source,args.purpose,
                    preview['Changes'],release.parse_template(session.client('cloudformation').get_template(ChangeSetName=record['changeSetArn'],TemplateStage='Processed')['TemplateBody']),release.parse_template(baseline['processed']))
                release.execute_retained(session.client('cloudformation'),session.client('s3'),record,
                    approved_digest=args.approved_digest,source_sha=args.source_sha,service=CONFIG['service'],
                    baseline=baseline,permissions=permissions,identity=identity,source_package=source,
                    authority_check=lambda:fresh_execute_authority(session,record,source,args.purpose,preview,release.parse_template(session.client('cloudformation').get_template(ChangeSetName=record['changeSetArn'],TemplateStage='Processed')['TemplateBody'])))
                session.client('cloudformation').get_waiter('stack_create_complete' if baseline.get('absent') else 'stack_update_complete').wait(StackName=record['stackId'])
                after=captured_baseline(session)
                before={r['LogicalResourceId']:r['PhysicalResourceId'] for r in baseline.get('resources',[])}
                current={r['LogicalResourceId']:r['PhysicalResourceId'] for r in after['resources']}
                release.require(all(current.get(k)==v for k,v in before.items() if not k.startswith('Thn') or 'Version' not in k),
                    'production_identity_verification_failed')
                print(json.dumps({'verified':True,'digest':record['digest'],'baselineSha256':release.sha(after)}))
        return 0
    except Exception as error:
        # Closed diagnostic codes only; never echo provider messages or inputs.
        code=str(error) if isinstance(error,release.ReleaseError) else type(error).__name__
        print('production_release_failed:'+code+'; retain preview and diagnose exact evidence before another run',file=sys.stderr)
        return 2
if __name__=='__main__':raise SystemExit(main())
