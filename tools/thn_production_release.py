"""Retained native production review. Never repackages during execution.

Source-only main integration is separate from this protected manual operation.
Raw templates/parameters/recovery bytes belong in private versioned S3; the
transported review record contains only identities, fingerprints and inventory.
"""
from copy import deepcopy
import hashlib
import json
import re
import time

ACCOUNT = '765932874577'
REGION = 'us-east-1'
CONTRACT = 'thn-production-retained-review/v1'
FIELDS = frozenset({'schemaVersion','contract','environment','service','purpose',
    'sourceSha','stackId','changeSetArn','createdAt','expiresAt','baselineSha256',
    'originalTemplateSha256','processedTemplateSha256','parametersSha256',
    'permissionSha256','identitySha256','sourcePackageSha256','packageManifest',
    'changes','nativeInventorySha256','recoveryCoordinates','digest'})
PURPOSES = frozenset({'state','activate','general','recover'})
SERVICES = frozenset({'auth','api','hub','image'})
DEPENDENCIES = frozenset({'AWS::Lambda::Permission','AWS::Lambda::Url',
    'AWS::Lambda::ResourcePolicy'})
RESOURCE_TYPES = frozenset({'AWS::Lambda::Function','AWS::Lambda::Version',
    'AWS::Lambda::Alias','AWS::Lambda::Permission','AWS::Lambda::Url',
    'AWS::Lambda::ResourcePolicy','AWS::DynamoDB::Table','AWS::S3::Bucket',
    'AWS::S3::BucketPolicy','AWS::IAM::Role','AWS::IAM::Policy','AWS::Logs::LogGroup',
    'AWS::Cognito::UserPool','AWS::Cognito::UserPoolClient','AWS::Cognito::UserPoolGroup',
    'AWS::ApiGatewayV2::Api','AWS::ApiGatewayV2::Stage','AWS::ApiGatewayV2::Authorizer',
    'AWS::ApiGatewayV2::Integration','AWS::ApiGatewayV2::Route','AWS::ApiGateway::RestApi',
    'AWS::ApiGateway::Stage','AWS::ApiGateway::Deployment','AWS::CloudWatch::Alarm',
    'AWS::SNS::Topic','AWS::SNS::Subscription','AWS::Events::Rule'})

class ReleaseError(ValueError):
    """Sanitized closed-contract failure; never include provider values."""

def require(condition, message='production_release_invalid'):
    if not condition: raise ReleaseError(message)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),default=str).encode()

def sha(value):
    return hashlib.sha256(value if isinstance(value,bytes) else canonical(value)).hexdigest()

def stable_simulation_evaluations(evaluations):
    """Preserve IAM evidence while ignoring provider ordering of equal results."""
    rows=deepcopy(evaluations)
    for row in rows:
        for key in ('MatchedStatements','MissingContextValues'):
            if key in row:row[key]=sorted(row[key],key=canonical)
        for resource in row.get('ResourceSpecificResults',[]):
            for key in ('MatchedStatements','MissingContextValues'):
                if key in resource:resource[key]=sorted(resource[key],key=canonical)
        if 'ResourceSpecificResults' in row:
            row['ResourceSpecificResults']=sorted(row['ResourceSpecificResults'],key=canonical)
    return sorted(rows,key=canonical)

def _sha(value,length=64):
    return isinstance(value,str) and bool(re.fullmatch('[a-f0-9]{'+str(length)+'}',value)) and value!='0'*length

def safe_inventory(changes):
    """Property contexts may contain Lambda configuration; fingerprint them."""
    return sorted([{'resource':{key:item.get('ResourceChange',{}).get(key) for key in
        ('Action','LogicalResourceId','PhysicalResourceId','ResourceType','Replacement','Scope')},
        'nativeChangeSha256':sha(item)} for item in changes],key=canonical)

def make_review_record(*,service,purpose,source_sha,stack_id,change_set_arn,
        created_at,baseline,original,processed,parameters,packages,changes,recovery,
        permissions=None,identity=None,source_package=None):
    require(service in SERVICES and purpose in PURPOSES and _sha(source_sha,40))
    require(type(created_at) is int)
    record={'schemaVersion':1,'contract':CONTRACT,'environment':'production',
        'service':service,'purpose':purpose,'sourceSha':source_sha,'stackId':stack_id,
        'changeSetArn':change_set_arn,'createdAt':created_at,'expiresAt':created_at+86400,
        'baselineSha256':sha(baseline),'originalTemplateSha256':sha(original),
        'processedTemplateSha256':sha(processed),'parametersSha256':sha(parameters),
        'permissionSha256':sha(permissions),'identitySha256':sha(identity),
        'sourcePackageSha256':sha(source_package),'packageManifest':deepcopy(packages),
        'changes':safe_inventory(changes),'nativeInventorySha256':sha(sorted(changes,key=canonical)),
        'recoveryCoordinates':deepcopy(recovery)}
    record['digest']=sha(record)
    return record

def verify_review_record(record,*,approved_digest,now,service,source_sha):
    require(isinstance(record,dict) and set(record)==FIELDS)
    require(type(record['schemaVersion']) is int and record['schemaVersion']==1)
    require(record['contract']==CONTRACT and record['environment']=='production')
    require(service in SERVICES and record['service']==service and record['purpose'] in PURPOSES)
    require(_sha(source_sha,40) and record['sourceSha']==source_sha)
    require(_sha(approved_digest) and record['digest']==approved_digest)
    require(sha({key:value for key,value in record.items() if key!='digest'})==approved_digest,
        'production_review_digest_mismatch')
    require(type(now) is int and type(record['createdAt']) is int and
        record['createdAt']<=now<record['expiresAt'] and record['expiresAt']-record['createdAt']==86400,
        'production_review_expired')
    for name in ('baselineSha256','originalTemplateSha256','processedTemplateSha256',
            'parametersSha256','permissionSha256','identitySha256','sourcePackageSha256','nativeInventorySha256'):
        require(_sha(record[name]))
    require(isinstance(record['packageManifest'],list) and isinstance(record['changes'],list)
        and isinstance(record['recoveryCoordinates'],list))
    for package in record['packageManifest']+record['recoveryCoordinates']:
        require(isinstance(package,dict) and set(package)=={'bucket','key','versionId','sha256'})
        require(all(isinstance(package[key],str) and package[key] for key in ('bucket','key','versionId'))
            and package['versionId']!='null' and _sha(package['sha256']))
    prefix=f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:'
    require(record['stackId'].startswith(prefix+'stack/'))
    require(record['changeSetArn'].startswith(prefix+f'changeSet/thn-production-{service}-'))
    return deepcopy(record)

def review_inventory(changes,old,new,*,scope):
    require(scope in PURPOSES and isinstance(changes,list))
    previous=old.get('Resources',{});candidate=new.get('Resources',{})
    seen=set()
    for item in changes:
        resource=item.get('ResourceChange',{})
        logical=resource.get('LogicalResourceId');kind=resource.get('ResourceType')
        action=resource.get('Action');replacement=resource.get('Replacement','False')
        require(isinstance(logical,str) and logical not in seen and kind in RESOURCE_TYPES)
        seen.add(logical)
        if action=='Remove':
            # SAM versions may leave the active alias; the immutable version stays retained.
            require(kind=='AWS::Lambda::Version' and previous.get(logical,{}).get('DeletionPolicy')=='Retain',
                'production_resource_deletion_blocked')
            continue
        require(action in {'Add','Modify'} and logical in candidate)
        target=candidate[logical]
        require(target.get('Type')==kind)
        if replacement!='False':
            require(replacement=='Conditional' and kind in DEPENDENCIES and
                previous.get(logical,{}).get('Properties')==target.get('Properties'),
                'production_identity_replacement_blocked')
        if scope in {'state','activate'}:
            require(logical.startswith(('Thn','ServiceBinding')) or
                (kind=='AWS::ApiGatewayV2::Api' and logical=='ContentHubApi') or
                (kind=='AWS::ApiGatewayV2::Stage' and logical=='ContentHubApiprodStage' and
                 target.get('Properties',{}).get('ApiId')=={'Ref':'ContentHubApi'} and
                 target.get('Properties',{}).get('StageName')=='prod'),
                'production_general_change_requires_own_review')
        if action=='Add' and kind in {'AWS::DynamoDB::Table','AWS::S3::Bucket',
                'AWS::Cognito::UserPool','AWS::Cognito::UserPoolClient','AWS::Logs::LogGroup'}:
            require(target.get('DeletionPolicy')=='Retain' and target.get('UpdateReplacePolicy')=='Retain',
                'production_state_retention_missing')
            props=target.get('Properties',{})
            if kind=='AWS::DynamoDB::Table':
                require(props.get('DeletionProtectionEnabled') is True and
                    props.get('PointInTimeRecoverySpecification',{}).get('PointInTimeRecoveryEnabled') is True)
            elif kind=='AWS::Cognito::UserPool':
                require(props.get('DeletionProtection')=='ACTIVE' and props.get('MfaConfiguration')=='ON')
            elif kind=='AWS::S3::Bucket':
                require(props.get('VersioningConfiguration',{}).get('Status')=='Enabled' and
                    all(props.get('PublicAccessBlockConfiguration',{}).get(k) is True for k in
                        ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')))
    return sorted(deepcopy(changes),key=canonical)

def select_parameters(definitions,current,overrides,*,purpose):
    require(purpose in PURPOSES and isinstance(overrides,dict) and not(set(overrides)-set(definitions)))
    previous={item['ParameterKey']:item for item in current}
    parameters=[]
    for name,definition in definitions.items():
        if name in overrides:
            value=overrides[name]
            require(isinstance(value,str) and value and value!='****')
            if name=='EnvironmentName': require(value=='prod')
            # A production input cannot select another environment's fixed identity.
            require(not any(marker in value for marker in ('admin-test.','thn-journal-test-v2',
                'zoolanding-auth-admin-test','zoolanding-content-hub-test','zoolanding-image-upload-test')))
            parameters.append({'ParameterKey':name,'ParameterValue':value})
        elif name in previous:
            parameters.append({'ParameterKey':name,'UsePreviousValue':True})
        elif 'Default' in definition:
            parameters.append({'ParameterKey':name,'ParameterValue':str(definition['Default'])})
        else:
            raise ReleaseError('production_parameter_unavailable')
    values={p['ParameterKey']:p.get('ParameterValue',previous.get(p['ParameterKey'],{}).get('ParameterValue')) for p in parameters}
    if purpose=='general':
        require(all(values[name]==previous.get(name,{}).get('ParameterValue','false')
            for name in values if name.startswith(('EnableThn','ProvisionThn'))),
            'production_general_must_preserve_private_lifecycle')
    if purpose=='state':
        require(all(value=='false' for name,value in values.items() if name.startswith('EnableThn')),
            'production_routes_must_remain_closed')
    if purpose=='state':
        require(any(value=='true' for name,value in values.items() if name.startswith('ProvisionThn')),
            'production_state_selection_missing')
    return parameters

def seal_object(s3,bucket,key,body):
    """Private versioned object only; never accept a null/unversioned recovery coordinate."""
    require(s3.get_bucket_versioning(Bucket=bucket).get('Status')=='Enabled')
    block=s3.get_public_access_block(Bucket=bucket)['PublicAccessBlockConfiguration']
    require(all(block.get(k) is True for k in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')))
    response=s3.put_object(Bucket=bucket,Key=key,Body=body,ServerSideEncryption='AES256',
        ChecksumSHA256=__import__('base64').b64encode(hashlib.sha256(body).digest()).decode(),IfNoneMatch='*')
    coordinate={'bucket':bucket,'key':key,'versionId':response.get('VersionId'),'sha256':sha(body)}
    verify_object(s3,coordinate)
    return coordinate

def verify_object(s3,coordinate):
    require(coordinate.get('versionId') not in {None,'','null'})
    response=s3.get_object(Bucket=coordinate['bucket'],Key=coordinate['key'],VersionId=coordinate['versionId'])
    body=response['Body'].read()
    require(sha(body)==coordinate['sha256'],'production_object_bytes_changed')
    return body

def snapshot(cf,stack_name):
    """Fingerprint input captured by the caller; never print or publish raw parameter values."""
    stack=cf.describe_stacks(StackName=stack_name)['Stacks'][0]
    require(stack.get('StackStatus') in {'CREATE_COMPLETE','UPDATE_COMPLETE','UPDATE_ROLLBACK_COMPLETE','REVIEW_IN_PROGRESS'})
    resources=[];token=None
    while True:
        kwargs={'StackName':stack_name}
        if token: kwargs['NextToken']=token
        page=cf.list_stack_resources(**kwargs);resources.extend(page['StackResourceSummaries'])
        token=page.get('NextToken')
        if not token: break
    clean=lambda value:{k:v for k,v in value.items() if k not in {'ResponseMetadata','LastUpdatedTimestamp','LastUpdatedTime','CreationTime'}}
    return {'stackId':stack['StackId'],'status':stack['StackStatus'],
        'terminationProtection':stack.get('EnableTerminationProtection'),'roleArn':stack.get('RoleARN'),
        'tags':sorted(stack.get('Tags',[]),key=lambda value:value['Key']),
        'parameters':sorted(stack.get('Parameters',[]),key=lambda p:p['ParameterKey']),
        'outputs':sorted(stack.get('Outputs',[]),key=lambda p:p['OutputKey']),
        'resources':sorted((clean(r) for r in resources),key=lambda r:r['LogicalResourceId']),
        'original':cf.get_template(StackName=stack_name,TemplateStage='Original')['TemplateBody'],
        'processed':cf.get_template(StackName=stack_name,TemplateStage='Processed')['TemplateBody']}

def describe_preview(cf,arn):
    result={};changes=[];token=None
    while True:
        kwargs={'ChangeSetName':arn,'IncludePropertyValues':True}
        if token: kwargs['NextToken']=token
        page=cf.describe_change_set(**kwargs);changes.extend(page.get('Changes',[]))
        if not result: result={k:v for k,v in page.items() if k not in {'Changes','NextToken','ResponseMetadata'}}
        token=page.get('NextToken')
        if not token: break
    result['Changes']=changes
    require(result.get('Status')=='CREATE_COMPLETE' and result.get('ExecutionStatus')=='AVAILABLE',
        'production_preview_unavailable')
    return result

def parse_template(value):
    if isinstance(value,dict): return value
    import yaml
    return yaml.safe_load(value)

def execute_retained(cf,s3,record,*,approved_digest,source_sha,service,baseline,
        permissions,identity,source_package,authority_check,now=None):
    now=int(time.time()) if now is None else now
    verify_review_record(record,approved_digest=approved_digest,now=now,service=service,source_sha=source_sha)
    require(sha(baseline)==record['baselineSha256'],'production_baseline_changed')
    require(sha(permissions)==record['permissionSha256'] and sha(identity)==record['identitySha256'],
        'production_permissions_changed')
    require(sha(source_package)==record['sourcePackageSha256'],'production_source_package_changed')
    for coordinate in record['packageManifest']+record['recoveryCoordinates']: verify_object(s3,coordinate)
    preview=describe_preview(cf,record['changeSetArn'])
    require(preview['StackId']==record['stackId'])
    require(safe_inventory(preview['Changes'])==record['changes'] and
        sha(sorted(preview['Changes'],key=canonical))==record['nativeInventorySha256'],
        'production_native_inventory_changed')
    original=parse_template(cf.get_template(ChangeSetName=record['changeSetArn'],TemplateStage='Original')['TemplateBody'])
    processed=parse_template(cf.get_template(ChangeSetName=record['changeSetArn'],TemplateStage='Processed')['TemplateBody'])
    require(sha(original)==record['originalTemplateSha256'] and sha(processed)==record['processedTemplateSha256'])
    require(sha(preview.get('Parameters',[]))==record['parametersSha256'])
    review_inventory(preview['Changes'],parse_template(baseline['processed']),processed,scope=record['purpose'])
    # This is the only execution mutation. No package/build/create-change-set call exists here.
    require(callable(authority_check),'production_fresh_source_authority_missing')
    authority_check()
    cf.execute_change_set(ChangeSetName=record['changeSetArn'],StackName=record['stackId'])
    return {'executed':True,'digest':record['digest'],'changeSetArn':record['changeSetArn']}

def cleanup_retained(cf,record,*,service,source_sha):
    verify_review_record(record,approved_digest=record['digest'],now=min(int(time.time()),record['expiresAt']-1),
        service=service,source_sha=source_sha)
    preview=describe_preview(cf,record['changeSetArn'])
    require(preview['StackId']==record['stackId'] and safe_inventory(preview['Changes'])==record['changes'] and
        sha(sorted(preview['Changes'],key=canonical))==record['nativeInventorySha256'])
    cf.delete_change_set(ChangeSetName=record['changeSetArn'],StackName=record['stackId'])
