"""Fail-closed guards for the reviewed, parameter-only THN owner transition.

This module never accepts a caller-selected principal, region, or resource list.
The protected workflow is responsible for gathering the deployed templates and
submitting its sealed change set only after these guards pass.
"""
import re
import json

from tools.thn_production_release import (
    describe_preview, safe_inventory, sha,
    stable_simulation_evaluations,
)
from tools.thn_production_native_permissions import selected_actions

ACCOUNT = '765932874577'
REGION = 'us-east-1'
STACK = 'zoolanding-auth-admin-prod'
HUMAN_PRINCIPAL = f'arn:aws:iam::{ACCOUNT}:user/Hector-admin'
OWNER_CONDITION = 'IsThnProductionOwnerOperatorV2Provisioned'
APPROVED_ORIGINAL_SHA = 'd0699c43ef8cf9f05f930612545cd2583d92c9baa636415fc23402e0349fad7c'
APPROVED_PROCESSED_SHA = '1e2fcc33ac21709f6e71cf9c3f730d7868068d5cb18e68515ee6e2e2c74a0030'
OWNER_RESOURCES = {
    'ThnProductionOwnerHumanOperatorRole': 'AWS::IAM::Role',
    'ThnProductionOwnerOperatorV2AliasPolicy': 'AWS::Lambda::ResourcePolicy',
    'ThnProductionOwnerOperatorV2ErrorsAlarm': 'AWS::CloudWatch::Alarm',
    'ThnProductionOwnerOperatorV2FunctionLogGroup': 'AWS::Logs::LogGroup',
    'ThnProductionOwnerOperatorV2FunctionRole': 'AWS::IAM::Role',
    'ThnProductionOwnerOperatorV2FunctionUrl': 'AWS::Lambda::Url',
    'ThnProductionOwnerOperatorV2Policy': 'AWS::IAM::Policy',
    'ThnProductionOwnerOperatorV2Function': 'AWS::Lambda::Function',
    'ThnProductionOwnerOperatorV2FunctionVersion70edfefcc3': 'AWS::Lambda::Version',
    'ThnProductionOwnerOperatorV2FunctionAliasproduction': 'AWS::Lambda::Alias',
}
GENERATED_OWNER_IDS = frozenset({
    'ThnProductionOwnerOperatorV2FunctionVersion70edfefcc3',
    'ThnProductionOwnerOperatorV2FunctionAliasproduction',
})
OVERRIDES = {
    'ProvisionThnProductionOwnerOperatorV2': 'true',
    'ThnProductionOwnerOperatorGate': 'CONFIRMED_PRODUCTION_OWNER_OPERATOR',
    'ThnProductionOwnerHumanPrincipalArn': HUMAN_PRINCIPAL,
}
REQUIRED_CURRENT = {
    'ProvisionThnAuthAdminV2State': 'true',
    'ProvisionThnProductionOwnerOperatorV2': 'false',
    'ThnProductionOwnerOperatorGate': 'BLOCKED',
    'ThnProductionOwnerHumanPrincipalArn': 'BLOCKED',
    'EnableThnAuthAdminV2': 'false',
}


class OwnerReleaseError(ValueError):
    """Closed-contract failure with no provider values or secrets."""


def _require(value, code):
    if not value:
        raise OwnerReleaseError(code)


def parse_owner_template(value):
    """The deployed production template is JSON; reject YAML or duplicate keys."""
    if isinstance(value, dict):
        return value
    _require(isinstance(value, str), 'production_owner_template_invalid')
    def unique_pairs(pairs):
        result = {}
        for key, item in pairs:
            _require(key not in result, 'production_owner_template_invalid')
            result[key] = item
        return result
    try:
        parsed = json.loads(value, object_pairs_hook=unique_pairs)
    except (ValueError, TypeError) as exc:
        raise OwnerReleaseError('production_owner_template_invalid') from exc
    _require(isinstance(parsed, dict), 'production_owner_template_invalid')
    return parsed


def assert_deployed_template_fingerprints(original, processed):
    _require(sha(original) == APPROVED_ORIGINAL_SHA and
             sha(processed) == APPROVED_PROCESSED_SHA,
             'production_owner_deployed_template_changed')
    return True


def validate_owner_templates(original, processed):
    """Require the exact owner resource graph in deployed SAM and native templates."""
    _require(isinstance(original, dict) and isinstance(processed, dict),
             'production_owner_template_invalid')
    _require(original.get('Transform') == 'AWS::Serverless-2016-10-31' and
             'Transform' not in processed,
             'production_owner_transform_invalid')
    source = original.get('Resources')
    native = processed.get('Resources')
    _require(isinstance(source, dict) and isinstance(native, dict),
             'production_owner_template_invalid')
    source_owner = {name for name, item in source.items()
                    if isinstance(item, dict) and item.get('Condition') == OWNER_CONDITION}
    native_owner = {name for name, item in native.items()
                    if isinstance(item, dict) and item.get('Condition') == OWNER_CONDITION}
    _require(source_owner == set(OWNER_RESOURCES) - GENERATED_OWNER_IDS and
             native_owner == set(OWNER_RESOURCES), 'production_owner_resource_set_invalid')
    for name, expected_type in OWNER_RESOURCES.items():
        _require(native[name].get('Type') == expected_type,
                 'production_owner_resource_type_invalid')
        if name not in GENERATED_OWNER_IDS:
            source_type = ('AWS::Serverless::Function' if
                           name == 'ThnProductionOwnerOperatorV2Function' else expected_type)
            _require(source[name].get('Type') == source_type,
                     'production_owner_resource_type_invalid')
    expected_trust = {'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Action': 'sts:AssumeRole',
        'Principal': {'AWS': {'Ref': 'ThnProductionOwnerHumanPrincipalArn'}},
        'Condition': {'Bool': {'aws:MultiFactorAuthPresent': 'true'},
                      'NumericLessThanEquals': {'aws:MultiFactorAuthAge': '300'}},
    }]}
    expected_role = {'RoleName': 'zoolanding-thn-owner-production-operator',
                     'MaxSessionDuration': 3600,
                     'AssumeRolePolicyDocument': expected_trust}
    expected_url = {'AuthType': 'AWS_IAM', 'InvokeMode': 'BUFFERED',
                    'Qualifier': 'production', 'TargetFunctionArn': {'Fn::GetAtt': [
                        'ThnProductionOwnerOperatorV2Function', 'Arn']}}
    for template in (original, processed):
        _require(template['Resources']['ThnProductionOwnerHumanOperatorRole']
                 .get('Properties') == expected_role,
                 'production_owner_trust_invalid')
        _require(template['Resources']['ThnProductionOwnerOperatorV2FunctionUrl']
                 .get('Properties') == expected_url,
                 'production_owner_url_invalid')
    _require(set(OVERRIDES) <= set(original.get('Parameters', {})) and
             set(REQUIRED_CURRENT) <= set(original.get('Parameters', {})),
             'production_owner_parameters_missing')
    return True


def owner_parameters(definitions, current):
    """Submit only three values; every other deployed parameter uses its prior value."""
    _require(isinstance(definitions, dict) and isinstance(current, list),
             'production_owner_parameters_invalid')
    names = [item.get('ParameterKey') for item in current if isinstance(item, dict)]
    _require(len(names) == len(current) and len(names) == len(set(names)) and
             set(names) == set(definitions), 'production_owner_parameters_invalid')
    previous = {item['ParameterKey']: item.get('ParameterValue') for item in current}
    _require(all(previous.get(key) == value for key, value in REQUIRED_CURRENT.items()),
             'production_owner_current_state_invalid')
    return [({'ParameterKey': name, 'ParameterValue': OVERRIDES[name]} if name in OVERRIDES
             else {'ParameterKey': name, 'UsePreviousValue': True})
            for name in definitions]


def validate_owner_inventory(changes, processed):
    """Accept exactly ten owner Adds and no modification or replacement."""
    _require(isinstance(changes, list) and isinstance(processed, dict),
             'production_owner_inventory_invalid')
    rows = []
    for item in changes:
        _require(isinstance(item, dict) and item.get('Type', 'Resource') == 'Resource' and
                 isinstance(item.get('ResourceChange'), dict),
                 'production_owner_inventory_invalid')
        row = item['ResourceChange']
        logical = row.get('LogicalResourceId')
        _require(logical in OWNER_RESOURCES and row.get('Action') == 'Add' and
                 row.get('ResourceType') == OWNER_RESOURCES[logical] and
                 row.get('Replacement', 'False') in (None, 'False', False) and
                 processed.get('Resources', {}).get(logical, {}).get('Type') ==
                 OWNER_RESOURCES[logical], 'production_owner_inventory_invalid')
        rows.append(logical)
    _require(len(rows) == len(OWNER_RESOURCES) and set(rows) == set(OWNER_RESOURCES),
             'production_owner_inventory_invalid')
    return True


_REVIEW_KEYS = frozenset({'schemaVersion', 'contract', 'environment',
    'sourceSha', 'stackId', 'changeSetArn', 'createdAt', 'expiresAt',
    'baselineSha256', 'originalTemplateSha256', 'processedTemplateSha256',
    'parametersSha256', 'identitySha256', 'permissionsSha256',
    'nativeInventorySha256', 'changes', 'digest'})
_STACK_ARN = re.compile(r'arn:aws:cloudformation:us-east-1:765932874577:stack/'
                        r'zoolanding-auth-admin-prod/[A-Za-z0-9-]+\Z')
_CHANGE_SET_ARN = re.compile(r'arn:aws:cloudformation:us-east-1:765932874577:changeSet/'
                             r'thn-production-auth-owner-[A-Za-z0-9-]+/[A-Za-z0-9-]+\Z')


def make_owner_review_record(*, source_sha, stack_id, change_set_arn, created_at,
                             baseline, original, processed, parameters, identity,
                             permissions, changes):
    """Seal sanitized review evidence for 24 hours; never transport raw secrets."""
    _require(isinstance(source_sha, str) and re.fullmatch(r'[a-f0-9]{40}', source_sha)
             and source_sha != '0' * 40 and isinstance(stack_id, str)
             and _STACK_ARN.fullmatch(stack_id) and isinstance(change_set_arn, str)
             and _CHANGE_SET_ARN.fullmatch(change_set_arn) and type(created_at) is int,
             'production_owner_review_input_invalid')
    validate_owner_templates(original, processed)
    validate_owner_inventory(changes, processed)
    record = {
        'schemaVersion': 1,
        'contract': 'thn-production-owner-parameter-review/v1',
        'environment': 'production',
        'sourceSha': source_sha,
        'stackId': stack_id,
        'changeSetArn': change_set_arn,
        'createdAt': created_at,
        'expiresAt': created_at + 86400,
        'baselineSha256': sha(baseline),
        'originalTemplateSha256': sha(original),
        'processedTemplateSha256': sha(processed),
        'parametersSha256': sha(parameters),
        'identitySha256': sha(identity),
        'permissionsSha256': sha(permissions),
        'nativeInventorySha256': sha(changes),
        'changes': safe_inventory(changes),
    }
    record['digest'] = sha(record)
    return record


def verify_owner_review_record(record, *, approved_digest, now, source_sha,
                               baseline, original, processed, parameters,
                               identity, permissions, changes):
    """Reject stale source, environment, permissions, preview, or approval."""
    _require(isinstance(record, dict) and set(record) == _REVIEW_KEYS and
             record.get('schemaVersion') == 1 and
             record.get('contract') == 'thn-production-owner-parameter-review/v1' and
             record.get('environment') == 'production',
             'production_owner_review_invalid')
    _require(type(now) is int and type(record['createdAt']) is int and
             type(record['expiresAt']) is int and
             record['createdAt'] <= now < record['expiresAt'] and
             record['expiresAt'] - record['createdAt'] == 86400,
             'production_owner_review_expired')
    _require(isinstance(approved_digest, str) and
             re.fullmatch(r'[a-f0-9]{64}', approved_digest) and
             record['digest'] == approved_digest and
             sha({key: value for key, value in record.items() if key != 'digest'}) ==
             approved_digest, 'production_owner_review_digest_mismatch')
    _require(record['sourceSha'] == source_sha and
             isinstance(record['stackId'], str) and _STACK_ARN.fullmatch(record['stackId']) and
             isinstance(record['changeSetArn'], str) and
             _CHANGE_SET_ARN.fullmatch(record['changeSetArn']),
             'production_owner_review_source_mismatch')
    validate_owner_templates(original, processed)
    validate_owner_inventory(changes, processed)
    expected = {
        'baselineSha256': sha(baseline),
        'originalTemplateSha256': sha(original),
        'processedTemplateSha256': sha(processed),
        'parametersSha256': sha(parameters),
        'identitySha256': sha(identity),
        'permissionsSha256': sha(permissions),
        'nativeInventorySha256': sha(changes),
        'changes': safe_inventory(changes),
    }
    _require(all(record[key] == value for key, value in expected.items()),
             'production_owner_review_baseline_mismatch')
    return True


def _owner_read_requests(stack_id):
    function = (f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:'
                'zoolanding-auth-admin-prod-ThnProductionOwnerOperatorV2')
    return [
        (f'arn:aws:iam::{ACCOUNT}:user/Hector-admin', ['iam:listmfadevices']),
        (f'arn:aws:cognito-idp:{REGION}:{ACCOUNT}:userpool/us-east-1_c1QxYjOiI',
         ['cognito-idp:listusersingroup']),
        (f'arn:aws:iam::{ACCOUNT}:role/zoolanding-thn-owner-production-operator',
         ['iam:getrole', 'iam:getrolepolicy', 'iam:listattachedrolepolicies',
          'iam:listrolepolicies']),
        (f'arn:aws:iam::{ACCOUNT}:role/zoolanding-auth-admin-prod-'
         'ThnProductionOwnerOperatorV2Role',
         ['iam:getrole', 'iam:getrolepolicy', 'iam:listattachedrolepolicies',
          'iam:listrolepolicies']),
        (function, ['lambda:getalias', 'lambda:getfunctionurlconfig']),
        (function + ':production', ['lambda:getalias', 'lambda:getfunctionurlconfig']),
        (stack_id, ['cloudformation:listchangesets']),
    ]


def prove_owner_deploy_reads(iam, stack_id):
    """Simulate every previously denied exact Auth role read before any write."""
    _require(isinstance(stack_id, str) and _STACK_ARN.fullmatch(stack_id),
             'production_owner_stack_invalid')
    role = f'arn:aws:iam::{ACCOUNT}:role/zoolanding-auth-admin-production-deploy'
    evidence = []
    for resource, actions in _owner_read_requests(stack_id):
        result = iam.simulate_principal_policy(PolicySourceArn=role,
            ActionNames=actions, ResourceArns=[resource])
        evaluations = result.get('EvaluationResults', [])
        _require(result.get('IsTruncated') is not True and len(evaluations) == len(actions)
                 and {row.get('EvalActionName', '').lower() for row in evaluations} ==
                 set(actions), 'production_owner_read_simulation_incomplete')
        for row in evaluations:
            nested = row.get('ResourceSpecificResults', [])
            covered = [item.get('EvalResourceName') for item in nested] if nested else [
                row.get('EvalResourceName')]
            _require(row.get('EvalDecision') == 'allowed' and
                     not row.get('MissingContextValues') and covered == [resource] and
                     all(item.get('EvalResourceDecision') == 'allowed' and
                         not item.get('MissingContextValues') for item in nested),
                     'production_owner_read_permission_denied')
        evidence.append({'resource': resource, 'actions': actions,
                         'evaluation': stable_simulation_evaluations(evaluations)})
    return evidence


def is_owner_manifest_row(row):
    """Allow only the historical SAM version suffix as a logical-ID alias."""
    if not isinstance(row, dict) or not isinstance(row.get('logicalIds'), list):
        return False
    kind = row.get('resourceType')
    return any(name in OWNER_RESOURCES and OWNER_RESOURCES[name] == kind or
               kind == 'AWS::Lambda::Version' and isinstance(name, str) and
               re.fullmatch(r'ThnProductionOwnerOperatorV2FunctionVersion[a-f0-9]{10}', name)
               for name in row['logicalIds'])


def prove_owner_native_permissions(cf, iam, processed, manifest):
    """Recompute native provider actions and simulate the execution role."""
    _require(isinstance(manifest, dict) and manifest.get('account') == ACCOUNT and
             manifest.get('region') == REGION and
             isinstance(manifest.get('proofMatrix'), list),
             'production_owner_native_manifest_invalid')
    selected = {}
    schema_hashes = {}
    role = (f'arn:aws:iam::{ACCOUNT}:role/'
            'zoolanding-deployer-auth-admin-production-cfn-exec')
    kinds = {kind for kind in OWNER_RESOURCES.values()}
    for kind in sorted(kinds):
        descriptor = cf.describe_type(Type='RESOURCE', TypeName=kind)
        raw = descriptor.get('Schema')
        _require(isinstance(raw, str), 'production_owner_native_schema_invalid')
        schema = json.loads(raw)
        changes = [{'Action': 'Add', 'LogicalResourceId': name}
                   for name, resource_type in OWNER_RESOURCES.items()
                   if resource_type == kind]
        selected[kind] = selected_actions(kind, schema['handlers'], changes,
                                          processed, processed)
        schema_hashes[kind] = sha(schema)
    rows = [row for row in manifest['proofMatrix']
            if row.get('group') == 'auth' and row.get('principalArn') == role
            and is_owner_manifest_row(row)]
    represented = {kind: set() for kind in kinds}
    groups = {}
    for row in rows:
        kind = row.get('resourceType')
        _require(kind in kinds and isinstance(row.get('actions'), list) and
                 isinstance(row.get('resources'), list) and
                 isinstance(row.get('condition'), dict),
                 'production_owner_native_manifest_invalid')
        actions = set(row['actions']) & selected[kind]
        if not actions:
            continue
        represented[kind].update(actions)
        resources = [resource for resource in row['resources']
                     if 'Owner' in resource or 'owner' in resource] or row['resources']
        for resource in resources:
            key = (resource, json.dumps(row['condition'], sort_keys=True))
            groups.setdefault(key, set()).update(actions)
    _require(all(represented[kind] == selected[kind] for kind in kinds),
             'production_owner_native_coverage_missing')
    proof = []
    for (resource, condition_json), actions in sorted(groups.items()):
        condition = json.loads(condition_json)
        entries = []
        for operator, mapping in condition.items():
            _require(operator == 'StringEquals' and isinstance(mapping, dict),
                     'production_owner_native_context_invalid')
            for name, value in mapping.items():
                entries.append({'ContextKeyName': name,
                                'ContextKeyValues': [value],
                                'ContextKeyType': 'string'})
        requested = sorted(actions)
        result = iam.simulate_principal_policy(PolicySourceArn=role,
            ActionNames=requested, ResourceArns=[resource], ContextEntries=entries)
        evaluations = result.get('EvaluationResults', [])
        _require(result.get('IsTruncated') is not True and
                 len(evaluations) == len(requested) and
                 {item.get('EvalActionName', '').lower() for item in evaluations} ==
                 {action.lower() for action in requested},
                 'production_owner_native_simulation_incomplete')
        for item in evaluations:
            nested = item.get('ResourceSpecificResults', [])
            covered = [entry.get('EvalResourceName') for entry in nested] if nested else [
                item.get('EvalResourceName')]
            _require(item.get('EvalDecision') == 'allowed' and
                     not item.get('MissingContextValues') and covered == [resource] and
                     all(entry.get('EvalResourceDecision') == 'allowed' and
                         not entry.get('MissingContextValues') for entry in nested),
                     'production_owner_native_permission_denied')
        proof.append({'resource': resource, 'actions': requested,
                      'condition': condition,
                      'evaluation': stable_simulation_evaluations(evaluations)})
    _require(sum(len(item['actions']) for item in proof) == 97,
             'production_owner_native_coverage_missing')
    return {'schemaHashes': schema_hashes, 'requests': proof}


def owner_change_set_request(current, *, run_id, attempt):
    """Build one parameter-only UPDATE request from the deployed stack state."""
    _require(isinstance(current, dict) and isinstance(current.get('stackId'), str)
             and _STACK_ARN.fullmatch(current['stackId']) and
             current.get('status') == 'UPDATE_COMPLETE' and
             current.get('terminationProtection') is True and
             current.get('roleArn') == f'arn:aws:iam::{ACCOUNT}:role/'
             'zoolanding-deployer-auth-admin-production-cfn-exec',
             'production_owner_stack_state_invalid')
    resources = current.get('resources')
    _require(isinstance(resources, list) and len(resources) == 37 and
             len({item.get('LogicalResourceId') for item in resources
                  if isinstance(item, dict)}) == 37 and
             all(isinstance(item, dict) and
                 isinstance(item.get('PhysicalResourceId'), str) and
                 item['PhysicalResourceId'] and
                 item['LogicalResourceId'] not in OWNER_RESOURCES
                 for item in resources), 'production_owner_stack_resources_invalid')
    _require(isinstance(current.get('tags'), list) and
             all(isinstance(tag, dict) and set(tag) == {'Key', 'Value'}
                 for tag in current['tags']), 'production_owner_stack_tags_invalid')
    _require(isinstance(run_id, str) and re.fullmatch(r'[0-9]{1,20}', run_id) and
             isinstance(attempt, str) and re.fullmatch(r'[0-9]{1,4}', attempt),
             'production_owner_run_invalid')
    validate_owner_templates(current.get('original'), current.get('processed'))
    selected = owner_parameters(current['original']['Parameters'],
                                current.get('parameters'))
    return {
        'StackName': current['stackId'],
        'ChangeSetName': f'thn-production-auth-owner-{run_id}-{attempt}',
        'ChangeSetType': 'UPDATE',
        'UsePreviousTemplate': True,
        'Parameters': selected,
        'Capabilities': ['CAPABILITY_NAMED_IAM'],
        'RoleARN': current['roleArn'],
        'Tags': current['tags'],
    }


def verify_owner_post(before, after):
    """Require the exact ten additions and immutable identities after execute."""
    _require(isinstance(before, dict) and isinstance(after, dict) and
             after.get('stackId') == before.get('stackId') and
             after.get('status') == 'UPDATE_COMPLETE' and
             after.get('terminationProtection') is True and
             after.get('roleArn') == before.get('roleArn') and
             after.get('tags') == before.get('tags') and
             sha(after.get('original')) == sha(before.get('original')) and
             sha(after.get('processed')) == sha(before.get('processed')),
             'production_owner_post_stack_changed')
    validate_owner_templates(before.get('original'), before.get('processed'))
    before_params = {item['ParameterKey']: item.get('ParameterValue')
                     for item in before.get('parameters', [])}
    after_params = {item['ParameterKey']: item.get('ParameterValue')
                    for item in after.get('parameters', [])}
    _require(len(before_params) == len(before.get('parameters', [])) and
             len(after_params) == len(after.get('parameters', [])) and
             set(before_params) == set(after_params) and
             all(after_params[name] == OVERRIDES.get(name, value)
                 for name, value in before_params.items()) and
             after_params.get('EnableThnAuthAdminV2') == 'false',
             'production_owner_post_parameters_changed')
    old_resources = before.get('resources')
    new_resources = after.get('resources')
    _require(isinstance(old_resources, list) and len(old_resources) == 37 and
             isinstance(new_resources, list) and len(new_resources) == 47,
             'production_owner_post_resources_changed')
    old = {item['LogicalResourceId']: item for item in old_resources}
    new = {item['LogicalResourceId']: item for item in new_resources}
    _require(len(old) == 37 and len(new) == 47 and
             set(new) == set(old) | set(OWNER_RESOURCES),
             'production_owner_post_resources_changed')
    _require(all(new[name].get('PhysicalResourceId') == item.get('PhysicalResourceId')
                 and new[name].get('ResourceType') == item.get('ResourceType')
                 for name, item in old.items()) and
             all(new[name].get('ResourceType') == kind and
                 isinstance(new[name].get('PhysicalResourceId'), str) and
                 new[name]['PhysicalResourceId']
                 for name, kind in OWNER_RESOURCES.items()),
             'production_owner_post_identity_changed')
    return True


def validate_owner_preview(preview, current, original, processed):
    """Reject a native change set unless only the ten pinned owner Adds remain."""
    _require(isinstance(preview, dict) and isinstance(current, dict) and
             preview.get('Status') == 'CREATE_COMPLETE' and
             preview.get('ExecutionStatus') == 'AVAILABLE' and
             preview.get('StackId') == current.get('stackId') and
             (preview.get('RoleARN') in (None, current.get('roleArn'))) and
             (preview.get('Capabilities') in (None, ['CAPABILITY_NAMED_IAM'])),
             'production_owner_preview_identity_invalid')
    validate_owner_templates(original, processed)
    _require(sha(original) == sha(current.get('original')) and
             sha(processed) == sha(current.get('processed')),
             'production_owner_preview_template_changed')
    prior = current.get('parameters')
    proposed = preview.get('Parameters')
    _require(isinstance(prior, list) and isinstance(proposed, list) and
             len(prior) == len(proposed), 'production_owner_preview_parameters_invalid')
    before = {item.get('ParameterKey'): item.get('ParameterValue') for item in prior}
    after = {item.get('ParameterKey'): item.get('ParameterValue') for item in proposed}
    _require(len(before) == len(prior) and len(after) == len(proposed) and
             set(before) == set(after) and
             all(after[name] == OVERRIDES.get(name, value)
                 for name, value in before.items()),
             'production_owner_preview_parameters_invalid')
    validate_owner_inventory(preview.get('Changes'), processed)
    return True


def run_owner_review(cf, *, preflight, source_sha, run_id, attempt, created_at):
    """Run the one protected preview after all read-only preflight checks."""
    _require(callable(preflight), 'production_owner_preflight_missing')
    current, identity, permissions = preflight()
    request = owner_change_set_request(current, run_id=run_id, attempt=attempt)
    change_set_arn = None
    try:
        response = cf.create_change_set(**request)
        change_set_arn = response.get('Id')
        _require(isinstance(change_set_arn, str) and
                 _CHANGE_SET_ARN.fullmatch(change_set_arn),
                 'production_owner_change_set_invalid')
        cf.get_waiter('change_set_create_complete').wait(
            ChangeSetName=change_set_arn, StackName=current['stackId'],
            WaiterConfig={'Delay': 5, 'MaxAttempts': 60})
        preview = describe_preview(cf, change_set_arn)
        original = parse_owner_template(cf.get_template(
            ChangeSetName=change_set_arn, TemplateStage='Original')['TemplateBody'])
        processed = parse_owner_template(cf.get_template(
            ChangeSetName=change_set_arn, TemplateStage='Processed')['TemplateBody'])
        validate_owner_preview(preview, current, original, processed)
        return make_owner_review_record(
            source_sha=source_sha, stack_id=current['stackId'],
            change_set_arn=change_set_arn, created_at=created_at,
            baseline=current, original=original, processed=processed,
            parameters=preview['Parameters'], identity=identity,
            permissions=permissions, changes=preview['Changes'])
    except Exception:
        if change_set_arn:
            try:
                cf.delete_change_set(ChangeSetName=change_set_arn,
                                     StackName=current['stackId'])
            except Exception as exc:
                raise OwnerReleaseError('production_owner_preview_cleanup_failed') from exc
        raise


def run_owner_execute(cf, *, record, approved_digest, source_sha, now,
                      preflight, postflight, authority_check,
                      verify_owner_runtime):
    """Re-prove the exact review and execute its original change set once."""
    _require(all(callable(value) for value in
                 (preflight, postflight, authority_check, verify_owner_runtime)),
             'production_owner_execute_guards_missing')
    current, identity, permissions = preflight()
    owner_change_set_request(current, run_id='1', attempt='1')
    _require(isinstance(record, dict) and isinstance(record.get('changeSetArn'), str)
             and _CHANGE_SET_ARN.fullmatch(record['changeSetArn']) and
             record.get('stackId') == current['stackId'],
             'production_owner_execute_record_invalid')
    preview = describe_preview(cf, record['changeSetArn'])
    original = parse_owner_template(cf.get_template(
        ChangeSetName=record['changeSetArn'], TemplateStage='Original')['TemplateBody'])
    processed = parse_owner_template(cf.get_template(
        ChangeSetName=record['changeSetArn'], TemplateStage='Processed')['TemplateBody'])
    validate_owner_preview(preview, current, original, processed)
    verify_owner_review_record(record, approved_digest=approved_digest, now=now,
        source_sha=source_sha, baseline=current, original=original,
        processed=processed, parameters=preview['Parameters'], identity=identity,
        permissions=permissions, changes=preview['Changes'])
    authority_check()
    cf.execute_change_set(ChangeSetName=record['changeSetArn'],
                          StackName=current['stackId'])
    cf.get_waiter('stack_update_complete').wait(StackName=current['stackId'],
        WaiterConfig={'Delay': 10, 'MaxAttempts': 120})
    after = postflight()
    verify_owner_post(current, after)
    verify_owner_runtime()
    return {'executed': True, 'digest': record['digest'],
            'changeSetArn': record['changeSetArn']}
