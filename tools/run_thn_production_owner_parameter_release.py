"""Manual, parameter-only production owner operator release.

No SAM build, package upload, owner enrollment, or route activation belongs to
this operation. Its preview is retained for a separate digest approval.
"""
import json
import argparse
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import thn_production_release as release
from tools import thn_production_owner_parameter_release as owner
from tools.run_thn_production_release import (
    load_json, source_selection, validate_github_trust,
)


MANIFEST = ROOT / 'tools/production/thn-deployment-identities.json'
DEPLOY_ROLE = 'zoolanding-auth-admin-production-deploy'
EXECUTION_ROLE = 'zoolanding-deployer-auth-admin-production-cfn-exec'
HUMAN_ROLE_ARN = ('arn:aws:iam::765932874577:role/'
                  'zoolanding-thn-owner-production-operator')
POOL_ID = 'us-east-1_c1QxYjOiI'


def _change_set_summaries(cf, stack_id):
    result = []
    token = None
    seen = set()
    while True:
        request = {'StackName': stack_id}
        if token:
            request['NextToken'] = token
        page = cf.list_change_sets(**request)
        summaries = page.get('Summaries')
        if not isinstance(summaries, list) or not all(
                isinstance(item, dict) and
                isinstance(item.get('ChangeSetId'), str) and
                item['ChangeSetId'] for item in summaries):
            raise owner.OwnerReleaseError('production_owner_change_set_list_invalid')
        result.extend(summaries)
        token = page.get('NextToken')
        if not token:
            return result
        if token in seen:
            raise owner.OwnerReleaseError('production_owner_change_set_pagination_invalid')
        seen.add(token)


def _owner_group_empty(cognito):
    token = None
    seen = set()
    while True:
        request = {'UserPoolId': POOL_ID, 'GroupName': 'journal-owner', 'Limit': 60}
        if token:
            request['NextToken'] = token
        result = cognito.list_users_in_group(**request)
        if result.get('Users') != []:
            raise owner.OwnerReleaseError('production_owner_group_not_empty')
        token = result.get('NextToken')
        if not token:
            return True
        if token in seen:
            raise owner.OwnerReleaseError('production_owner_group_pagination_invalid')
        seen.add(token)


def owner_package_state(session, original, processed):
    """Require the deployed owner ZIP's exact private version to remain readable."""
    source = original['Resources']['ThnProductionOwnerOperatorV2Function'][
        'Properties']['CodeUri']
    native = processed['Resources']['ThnProductionOwnerOperatorV2Function'][
        'Properties']['Code']
    if not isinstance(source, dict) or native != {
            'S3Bucket': source.get('Bucket'), 'S3Key': source.get('Key'),
            'S3ObjectVersion': source.get('Version')} or \
            source.get('Bucket') != (
                'zlp-thn-production-releases-765932874577-us-east-1') or \
            not isinstance(source.get('Key'), str) or \
            not source['Key'].startswith('thn/production/auth/') or \
            not isinstance(source.get('Version'), str) or not source['Version']:
        raise owner.OwnerReleaseError('production_owner_package_coordinate_invalid')
    arn = 'arn:aws:s3:::' + source['Bucket'] + '/' + source['Key']
    simulation = session.client('iam').simulate_principal_policy(
        PolicySourceArn=f'arn:aws:iam::{owner.ACCOUNT}:role/{DEPLOY_ROLE}',
        ActionNames=['s3:getobjectversion'], ResourceArns=[arn])
    evaluations = simulation.get('EvaluationResults', [])
    row = evaluations[0] if len(evaluations) == 1 else {}
    nested = row.get('ResourceSpecificResults', [])
    covered = ([item.get('EvalResourceName') for item in nested] if nested else
               [row.get('EvalResourceName')])
    if simulation.get('IsTruncated') is True or len(evaluations) != 1 or \
            row.get('EvalActionName', '').lower() != \
            's3:getobjectversion' or covered != [arn] or \
            row.get('EvalDecision') != 'allowed' or \
            row.get('MissingContextValues') or \
            any(item.get('EvalResourceDecision') != 'allowed' or
                item.get('MissingContextValues') for item in nested):
        raise owner.OwnerReleaseError('production_owner_package_read_denied')
    metadata = session.client('s3').head_object(
        Bucket=source['Bucket'], Key=source['Key'], VersionId=source['Version'])
    if metadata.get('VersionId') != source['Version'] or \
            type(metadata.get('ContentLength')) is not int or \
            metadata['ContentLength'] <= 0 or \
            metadata.get('ServerSideEncryption') != 'AES256' or \
            metadata.get('DeleteMarker') is True:
        raise owner.OwnerReleaseError('production_owner_package_unavailable')
    return {'coordinateSha256': release.sha(source),
            'versionId': source['Version'],
            'contentLength': metadata['ContentLength'],
            'encryption': 'AES256'}


def capture_owner_preflight(session, *, allowed_change_set_arn=None):
    """Refresh and fingerprint every production trust anchor before a write."""
    if session.region_name != owner.REGION:
        raise owner.OwnerReleaseError('production_owner_region_invalid')
    sts = session.client('sts')
    caller = sts.get_caller_identity()
    if caller.get('Account') != owner.ACCOUNT or not re.fullmatch(
            rf'arn:aws:sts::{owner.ACCOUNT}:assumed-role/{DEPLOY_ROLE}/[^/]+',
            caller.get('Arn', '')):
        raise owner.OwnerReleaseError('production_owner_caller_invalid')
    cf = session.client('cloudformation')
    state = release.snapshot(cf, owner.STACK)
    state['original'] = owner.parse_owner_template(state['original'])
    state['processed'] = owner.parse_owner_template(state['processed'])
    owner.assert_deployed_template_fingerprints(state['original'], state['processed'])
    owner.owner_change_set_request(state, run_id='1', attempt='1')
    summaries = _change_set_summaries(cf, state['stackId'])
    expected = ([{'ChangeSetId': allowed_change_set_arn,
                  'Status': 'CREATE_COMPLETE', 'ExecutionStatus': 'AVAILABLE'}]
                if allowed_change_set_arn else [])
    actual = [{key: item.get(key) for key in
               ('ChangeSetId', 'Status', 'ExecutionStatus')} for item in summaries]
    if actual != expected:
        raise owner.OwnerReleaseError('production_owner_competing_change_set')
    iam = session.client('iam')
    role = iam.get_role(RoleName=DEPLOY_ROLE)['Role']
    if role.get('Arn') != f'arn:aws:iam::{owner.ACCOUNT}:role/{DEPLOY_ROLE}':
        raise owner.OwnerReleaseError('production_owner_deploy_role_invalid')
    validate_github_trust(role['AssumeRolePolicyDocument'])
    mfa = iam.list_mfa_devices(UserName='Hector-admin')
    if mfa.get('IsTruncated') is True or len(mfa.get('MFADevices', [])) != 1:
        raise owner.OwnerReleaseError('production_owner_human_mfa_invalid')
    _owner_group_empty(session.client('cognito-idp'))
    human = iam.simulate_principal_policy(
        PolicySourceArn=owner.HUMAN_PRINCIPAL,
        ActionNames=['sts:assumerole'], ResourceArns=[HUMAN_ROLE_ARN],
        ContextEntries=[
            {'ContextKeyName': 'aws:MultiFactorAuthPresent',
             'ContextKeyValues': ['true'], 'ContextKeyType': 'boolean'},
            {'ContextKeyName': 'aws:MultiFactorAuthAge',
             'ContextKeyValues': ['120'], 'ContextKeyType': 'numeric'},
        ])
    evaluations = human.get('EvaluationResults', [])
    if human.get('IsTruncated') is True or len(evaluations) != 1 or \
            evaluations[0].get('EvalActionName', '').lower() != 'sts:assumerole' or \
            evaluations[0].get('EvalResourceName') != HUMAN_ROLE_ARN or \
            evaluations[0].get('EvalDecision') != 'allowed' or \
            evaluations[0].get('MissingContextValues'):
        raise owner.OwnerReleaseError('production_owner_human_assume_denied')
    reads = owner.prove_owner_deploy_reads(iam, state['stackId'])
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    native = owner.prove_owner_native_permissions(cf, iam, state['processed'], manifest)
    identity = {'callerArn': caller['Arn'], 'deployRoleId': role['RoleId'],
                'deployTrustSha256': release.sha(role['AssumeRolePolicyDocument']),
                'humanMfaDevices': 1, 'journalOwnerUsers': 0,
                'humanAssume': release.stable_simulation_evaluations(evaluations)}
    package = owner_package_state(session, state['original'], state['processed'])
    permissions = {'deployReads': reads, 'native': native, 'ownerPackage': package}
    return state, identity, permissions


def capture_owner_post(session):
    state = release.snapshot(session.client('cloudformation'), owner.STACK)
    state['original'] = owner.parse_owner_template(state['original'])
    state['processed'] = owner.parse_owner_template(state['processed'])
    return state


def verify_owner_runtime(session):
    """Read-only verification; never invoke the mediator or enroll an owner."""
    iam = session.client('iam')
    role = iam.get_role(RoleName='zoolanding-thn-owner-production-operator')['Role']
    if role.get('Arn') != HUMAN_ROLE_ARN:
        raise owner.OwnerReleaseError('production_owner_runtime_role_invalid')
    deployed = capture_owner_post(session)
    owner.assert_deployed_template_fingerprints(
        deployed['original'], deployed['processed'])
    expected = deployed['original']['Resources'][
        'ThnProductionOwnerHumanOperatorRole']['Properties']['AssumeRolePolicyDocument']
    expected = json.loads(json.dumps(expected))
    if expected['Statement'][0]['Principal'] != {
            'AWS': {'Ref': 'ThnProductionOwnerHumanPrincipalArn'}}:
        raise owner.OwnerReleaseError('production_owner_runtime_trust_invalid')
    expected['Statement'][0]['Principal'] = {'AWS': owner.HUMAN_PRINCIPAL}
    if release.sha(role.get('AssumeRolePolicyDocument')) != release.sha(expected):
        raise owner.OwnerReleaseError('production_owner_runtime_trust_invalid')
    inline = iam.list_role_policies(RoleName='zoolanding-thn-owner-production-operator')
    attached = iam.list_attached_role_policies(
        RoleName='zoolanding-thn-owner-production-operator')
    if inline.get('IsTruncated') or sorted(inline.get('PolicyNames', [])) != [
            'OperateExactThnOwnerV2'] or attached.get('IsTruncated') or \
            attached.get('AttachedPolicies') != []:
        raise owner.OwnerReleaseError('production_owner_runtime_role_policies_invalid')
    function = 'zoolanding-auth-admin-prod-ThnProductionOwnerOperatorV2'
    function_arn = f'arn:aws:lambda:{owner.REGION}:{owner.ACCOUNT}:function:{function}:production'
    statement = [
        {'Sid': 'ReadExactThnOwnerMediatorUrl', 'Effect': 'Allow',
         'Action': ['lambda:GetFunctionUrlConfig'], 'Resource': function_arn},
        {'Sid': 'InvokeExactThnOwnerMediatorUrl', 'Effect': 'Allow',
         'Action': ['lambda:InvokeFunctionUrl'], 'Resource': function_arn,
         'Condition': {'StringEquals': {'lambda:FunctionUrlAuthType': 'AWS_IAM'}}},
        {'Sid': 'InvokeExactThnOwnerMediatorOnlyViaUrl', 'Effect': 'Allow',
         'Action': ['lambda:InvokeFunction'], 'Resource': function_arn,
         'Condition': {'Bool': {'lambda:InvokedViaFunctionUrl': 'true'}}},
    ]
    role_policy = iam.get_role_policy(
        RoleName='zoolanding-thn-owner-production-operator',
        PolicyName='OperateExactThnOwnerV2')
    if role_policy.get('PolicyDocument') != {
            'Version': '2012-10-17', 'Statement': statement}:
        raise owner.OwnerReleaseError('production_owner_runtime_policy_invalid')
    lam = session.client('lambda')
    alias = lam.get_alias(FunctionName=function, Name='production')
    config = lam.get_function_url_config(FunctionName=function, Qualifier='production')
    if alias.get('Name') != 'production' or not re.fullmatch(
            r'[1-9][0-9]*', str(alias.get('FunctionVersion', ''))) or \
            config.get('AuthType') != 'AWS_IAM' or \
            config.get('InvokeMode') != 'BUFFERED' or \
            not re.fullmatch(r'https://[a-z0-9-]+\.lambda-url\.us-east-1\.on\.aws/',
                             str(config.get('FunctionUrl', ''))):
        raise owner.OwnerReleaseError('production_owner_runtime_url_invalid')
    _owner_group_empty(session.client('cognito-idp'))
    return True


def make_session():
    import boto3
    return boto3.Session(region_name=owner.REGION)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('validate', 'review', 'execute'))
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--review-run-id', default='')
    parser.add_argument('--approved-digest', default='')
    parser.add_argument('--record', default='production-owner-review.json')
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r'[a-f0-9]{40}', args.source_sha) or \
                args.source_sha == '0' * 40:
            raise owner.OwnerReleaseError('production_owner_source_invalid')
        source = source_selection(args.source_sha)
        if args.operation == 'validate':
            return 0
        record = None
        if args.operation == 'execute':
            if not re.fullmatch(r'[1-9][0-9]*', args.review_run_id) or \
                    not re.fullmatch(r'[a-f0-9]{64}', args.approved_digest):
                raise owner.OwnerReleaseError('production_owner_execute_inputs_invalid')
            record = load_json(Path(args.record).read_text(encoding='utf-8'))
            name = record.get('changeSetArn', '').split('/')[1:2]
            if record.get('sourceSha') != args.source_sha or \
                    record.get('digest') != args.approved_digest or \
                    len(name) != 1 or not re.fullmatch(
                        rf'thn-production-auth-owner-{re.escape(args.review_run_id)}-[1-9][0-9]{{0,3}}',
                        name[0]):
                raise owner.OwnerReleaseError('production_owner_review_provenance_invalid')
        if os.environ.get('AWS_ROLE_ARN') != \
                f'arn:aws:iam::{owner.ACCOUNT}:role/{DEPLOY_ROLE}':
            raise owner.OwnerReleaseError('production_owner_selected_role_invalid')
        session = make_session()
        cf = session.client('cloudformation')
        if args.operation == 'review':
            if args.review_run_id or args.approved_digest:
                raise owner.OwnerReleaseError('production_owner_review_inputs_invalid')
            def preflight():
                if source_selection(args.source_sha) != source:
                    raise owner.OwnerReleaseError('production_owner_source_changed')
                return capture_owner_preflight(session)
            record = owner.run_owner_review(cf, preflight=preflight,
                source_sha=args.source_sha,
                run_id=os.environ.get('GITHUB_RUN_ID', ''),
                attempt=os.environ.get('GITHUB_RUN_ATTEMPT', ''),
                created_at=int(time.time()))
            Path(args.record).write_text(json.dumps(record, sort_keys=True,
                indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'digest': record['digest'],
                'changeSetArn': record['changeSetArn'],
                'changes': record['changes'], 'expiresAt': record['expiresAt']}))
            return 0
        def preflight():
            if source_selection(args.source_sha) != source:
                raise owner.OwnerReleaseError('production_owner_source_changed')
            return capture_owner_preflight(session,
                allowed_change_set_arn=record['changeSetArn'])
        def authority_check():
            current, identity, permissions = preflight()
            if release.sha(current) != record.get('baselineSha256') or \
                    release.sha(identity) != record.get('identitySha256') or \
                    release.sha(permissions) != record.get('permissionsSha256'):
                raise owner.OwnerReleaseError('production_owner_fresh_authority_changed')
        result = owner.run_owner_execute(cf, record=record,
            approved_digest=args.approved_digest, source_sha=args.source_sha,
            now=int(time.time()), preflight=preflight,
            postflight=lambda: capture_owner_post(session),
            authority_check=authority_check,
            verify_owner_runtime=lambda: verify_owner_runtime(session))
        print(json.dumps({'verified': True, 'digest': result['digest']}))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, (owner.OwnerReleaseError,
                                                release.ReleaseError)) else type(error).__name__
        print('production_owner_release_failed:' + code, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
