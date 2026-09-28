"""Offline projection of retained THN production state from reviewed source.

Never deploys. V1 resources are copied unchanged. The TEST owner/QA mediator is
excluded; production ownership requires a separately reviewed dedicated operator.
Activation remains closed until that prerequisite gate is independently proved.
"""
from copy import deepcopy
import json
import sys
from pathlib import Path

ANCHORS = {
    "zoolanding-auth-admin-test-": "zoolanding-auth-admin-prod-",
    "zoolanding-content-hub-test-": "zoolanding-content-hub-prod-",
    "zoolanding-auth-test-ThnV2OriginAuthorizer": "zoolanding-auth-prod-ThnV2OriginAuthorizer",
    "SERVICE_BINDING#test#thn-journal-test-v2": "SERVICE_BINDING#production#thn-journal-production-v2",
    "CURRENT_USER#test#thn-journal-test-v2": "CURRENT_USER#production#thn-journal-production-v2",
    "AUDIT#test#thn-journal-test-v2": "AUDIT#production#thn-journal-production-v2",
    "zoolanding-thn-registry-test-operator": "zoolanding-thn-registry-production-operator",
}

def _project(value):
    if isinstance(value,dict): return {key:_project(item) for key,item in value.items()}
    if isinstance(value,list): return [_project(item) for item in value]
    if not isinstance(value,str): return value
    if value=="test": return "prod"
    for old,new in ANCHORS.items(): value=value.replace(old,new)
    value=value.replace("stack/zoolanding-auth-admin-test/", "stack/zoolanding-auth-admin-prod/")
    value=value.replace("/test/","/prod/")
    value=value.replace("ThnOwnerOperatorV2Role", "ThnProductionOwnerOperatorV2Role")
    if "-test-" in value or "#test#" in value or "admin-test." in value:
        raise ValueError("production_source_identity_unrecognized")
    return value

def prepare_template(source):
    if not isinstance(source,dict) or source.get('Transform')!='AWS::Serverless-2016-10-31':
        raise ValueError('production_source_invalid')
    resources=source.get('Resources',{})
    required={'ThnAuthAdminV2Function','ThnAuthAdminV2Api','ThnAuthAdminV2CurrentUserStateTable','AuthAdminFunction'}
    if not required.issubset(resources): raise ValueError('production_source_resources_invalid')
    result=deepcopy(source)
    result['Parameters']['EnvironmentName']['Default']='prod'
    result['Parameters']['EnvironmentName']['AllowedValues']=['prod']
    result['Parameters']['ThnProductionOwnerOperatorGate']={'Type':'String','Default':'BLOCKED','AllowedValues':['BLOCKED','CONFIRMED_PRODUCTION_OWNER_OPERATOR']}
    for key in ('Rules','Conditions','Metadata'):
        result[key]=_project(result.get(key,{}))
    result['Rules']['ThnAuthAdminV2ActivationRule']['Assertions'].append({'Assert':{'Fn::Equals':[{'Ref':'ThnProductionOwnerOperatorGate'},'CONFIRMED_PRODUCTION_OWNER_OPERATOR']},'AssertDescription':'The independently reviewed production owner operator must be verified before route activation.'})
    for logical in list(result['Resources']):
        if not logical.startswith('ThnAuthAdminV2'): continue
        if 'OwnerOperator' in logical:
            del result['Resources'][logical]
            continue
        result['Resources'][logical]=_project(result['Resources'][logical])
    for logical in ('ThnAuthAdminV2Function','ThnAuthAdminV2OriginAuthorizerFunction'):
        variables=result['Resources'][logical]['Properties']['Environment']['Variables']
        variables['THN_DEPLOYMENT_ENVIRONMENT']='production'
    result['Parameters']['ProvisionThnProductionOwnerOperatorV2']={'Type':'String','Default':'false','AllowedValues':['false','true']}
    result['Conditions']['IsThnProductionOwnerOperatorV2Provisioned']={'Fn::And':[{'Condition':'IsThnAuthAdminV2StateProvisioned'},{'Fn::Equals':[{'Ref':'ProvisionThnProductionOwnerOperatorV2'},'true']}]}
    result['Rules']['ThnProductionOwnerOperatorV2Rule']={'RuleCondition':{'Fn::Equals':[{'Ref':'ProvisionThnProductionOwnerOperatorV2'},'true']},'Assertions':[{'Assert':{'Fn::Equals':[{'Ref':'ProvisionThnAuthAdminV2State'},'true']},'AssertDescription':'Production owner operator requires separately retained auth state.'},{'Assert':{'Fn::Equals':[{'Ref':'ThnProductionOwnerOperatorGate'},'CONFIRMED_PRODUCTION_OWNER_OPERATOR']},'AssertDescription':'The exact production human operator IAM role must be verified independently.'}]}
    def owner_projection(value):
        if isinstance(value,dict): return {key:owner_projection(item) for key,item in value.items()}
        if isinstance(value,list): return [owner_projection(item) for item in value]
        if not isinstance(value,str): return value
        value=value.replace('ThnAuthAdminV2OwnerOperatorFunction','ThnProductionOwnerOperatorV2Function').replace('ThnAuthAdminV2OwnerOperator','ThnProductionOwnerOperatorV2')
        value=value.replace('zoolanding-thn-registry-test-operator','zoolanding-thn-owner-production-operator').replace('ThnOwnerOperatorV2','ThnProductionOwnerOperatorV2').replace('Aliastest','Aliasproduction').replace(':test',':production')
        value=value.replace('auth_admin_owner_operator_v2.lambda_handler','auth_admin_production_owner_operator_v2.lambda_handler')
        return 'production' if value=='test' else _project(value)
    for logical,value in source['Resources'].items():
        if not logical.startswith('ThnAuthAdminV2OwnerOperator'): continue
        name=owner_projection(logical)
        item=owner_projection(value)
        item['Condition']='IsThnProductionOwnerOperatorV2Provisioned'
        if item['Type']=='AWS::Serverless::Function':
            item['Properties'].setdefault('Environment',{}).setdefault('Variables',{})['THN_DEPLOYMENT_ENVIRONMENT']='production'
            item['Properties']['Description']='Separate audited production client-owner lifecycle. No QA operations.'
        result['Resources'][name]=item
    result['Parameters']['ThnProductionOwnerHumanPrincipalArn']={'Type':'String','Default':'BLOCKED','AllowedPattern':'^(BLOCKED|arn:aws:iam::765932874577:user/[A-Za-z0-9+=,.@_/-]+)$'}
    result['Rules']['ThnProductionOwnerOperatorV2Rule']['Assertions'].append({'Assert':{'Fn::Not':[{'Fn::Equals':[{'Ref':'ThnProductionOwnerHumanPrincipalArn'},'BLOCKED']}]},'AssertDescription':'The exact MFA-protected human IAM principal requires separate approval.'})
    result['Resources']['ThnProductionOwnerHumanOperatorRole']={'Type':'AWS::IAM::Role','Condition':'IsThnProductionOwnerOperatorV2Provisioned','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{'RoleName':'zoolanding-thn-owner-production-operator','MaxSessionDuration':3600,'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'AWS':{'Ref':'ThnProductionOwnerHumanPrincipalArn'}},'Condition':{'Bool':{'aws:MultiFactorAuthPresent':'true'},'NumericLessThanEquals':{'aws:MultiFactorAuthAge':'300'}}}]}}}
    result['Resources']['ThnProductionOwnerOperatorV2Policy']['Properties']['Roles']=[{'Ref':'ThnProductionOwnerHumanOperatorRole'}]
    result['Metadata']['ThnProductionLifecycle']={'Profile':'production','SAMEnvironment':'prod','OwnerOperator':'separate-reviewed-production-operation-required','AutomaticActivation':False}
    return result

def main(argv=None):
    import yaml
    args=sys.argv[1:] if argv is None else argv
    if len(args)!=2: raise ValueError('production_template_arguments_invalid')
    source=yaml.safe_load(Path(args[0]).read_text(encoding='utf-8'))
    Path(args[1]).write_text(json.dumps(prepare_template(source),sort_keys=True,indent=2)+'\n',encoding='utf-8')
    return 0
if __name__=='__main__': raise SystemExit(main())
