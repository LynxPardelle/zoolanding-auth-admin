"""Closed-contract tests for the parameter-only production owner transition."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from tools import thn_production_owner_parameter_release as owner


class OwnerParameterGuards(unittest.TestCase):
    def setUp(self):
        self.original = {
            'Transform': 'AWS::Serverless-2016-10-31',
            'Parameters': {
                'ProvisionThnAuthAdminV2State': {'Type': 'String'},
                'ProvisionThnProductionOwnerOperatorV2': {'Type': 'String'},
                'ThnProductionOwnerOperatorGate': {'Type': 'String'},
                'ThnProductionOwnerHumanPrincipalArn': {'Type': 'String'},
                'EnableThnAuthAdminV2': {'Type': 'String'},
                'LegacySecret': {'Type': 'String', 'NoEcho': True},
            },
            'Resources': {'Existing': {'Type': 'AWS::DynamoDB::Table'}},
        }
        self.original['Resources'].update({
            logical: {'Type': 'AWS::Serverless::Function' if logical ==
                'ThnProductionOwnerOperatorV2Function' else kind,
                'Condition': owner.OWNER_CONDITION}
            for logical, kind in owner.OWNER_RESOURCES.items()
            if logical not in owner.GENERATED_OWNER_IDS
        })
        self.original['Resources']['ThnProductionOwnerHumanOperatorRole']['Properties'] = {
            'RoleName': 'zoolanding-thn-owner-production-operator',
            'MaxSessionDuration': 3600,
            'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{
                'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                'Principal': {'AWS': {'Ref': 'ThnProductionOwnerHumanPrincipalArn'}},
                'Condition': {'Bool': {'aws:MultiFactorAuthPresent': 'true'},
                              'NumericLessThanEquals': {'aws:MultiFactorAuthAge': '300'}},
            }]},
        }
        self.original['Resources']['ThnProductionOwnerOperatorV2FunctionUrl']['Properties'] = {
            'AuthType': 'AWS_IAM', 'InvokeMode': 'BUFFERED',
            'Qualifier': 'production', 'TargetFunctionArn': {'Fn::GetAtt': [
                'ThnProductionOwnerOperatorV2Function', 'Arn']},
        }
        self.processed = deepcopy(self.original)
        del self.processed['Transform']
        for logical in owner.GENERATED_OWNER_IDS:
            self.processed['Resources'][logical] = {'Type': owner.OWNER_RESOURCES[logical],
                'Condition': owner.OWNER_CONDITION}
        self.processed['Resources']['ThnProductionOwnerOperatorV2Function']['Type'] = 'AWS::Lambda::Function'
        self.current = [
            {'ParameterKey': 'ProvisionThnAuthAdminV2State', 'ParameterValue': 'true'},
            {'ParameterKey': 'ProvisionThnProductionOwnerOperatorV2', 'ParameterValue': 'false'},
            {'ParameterKey': 'ThnProductionOwnerOperatorGate', 'ParameterValue': 'BLOCKED'},
            {'ParameterKey': 'ThnProductionOwnerHumanPrincipalArn', 'ParameterValue': 'BLOCKED'},
            {'ParameterKey': 'EnableThnAuthAdminV2', 'ParameterValue': 'false'},
            {'ParameterKey': 'LegacySecret', 'ParameterValue': '****'},
        ]

    def test_exact_three_overrides_keep_every_other_value_previous(self):
        selected = owner.owner_parameters(self.original['Parameters'], self.current)
        self.assertEqual(len(selected), len(self.current))
        actual = {item['ParameterKey']: item for item in selected}
        self.assertEqual(actual['ProvisionThnProductionOwnerOperatorV2']['ParameterValue'], 'true')
        self.assertEqual(actual['ThnProductionOwnerOperatorGate']['ParameterValue'],
                         'CONFIRMED_PRODUCTION_OWNER_OPERATOR')
        self.assertEqual(actual['ThnProductionOwnerHumanPrincipalArn']['ParameterValue'],
                         'arn:aws:iam::765932874577:user/Hector-admin')
        for name in ('ProvisionThnAuthAdminV2State', 'EnableThnAuthAdminV2', 'LegacySecret'):
            self.assertEqual(actual[name], {'ParameterKey': name, 'UsePreviousValue': True})

    def test_deployed_json_template_parser_rejects_ambiguous_source(self):
        self.assertEqual(owner.parse_owner_template(json.dumps(self.original)), self.original)
        for source in ('Resources: {}', '{"Resources":{},"Resources":{}}'):
            with self.subTest(source=source), self.assertRaises(owner.OwnerReleaseError):
                owner.parse_owner_template(source)

    def test_review_pins_both_full_deployed_template_fingerprints(self):
        from tools.thn_production_release import sha
        with patch.object(owner, 'APPROVED_ORIGINAL_SHA', sha(self.original)), \
             patch.object(owner, 'APPROVED_PROCESSED_SHA', sha(self.processed)):
            owner.assert_deployed_template_fingerprints(self.original, self.processed)
            wrong = deepcopy(self.processed)
            wrong['Resources']['Existing']['Type'] = 'AWS::S3::Bucket'
            with self.assertRaises(owner.OwnerReleaseError):
                owner.assert_deployed_template_fingerprints(self.original, wrong)

    def test_parameter_selection_fails_if_routes_open_or_owner_already_enabled(self):
        for name, value in (
            ('EnableThnAuthAdminV2', 'true'),
            ('ProvisionThnProductionOwnerOperatorV2', 'true'),
            ('ThnProductionOwnerOperatorGate', 'CONFIRMED_PRODUCTION_OWNER_OPERATOR'),
            ('ThnProductionOwnerHumanPrincipalArn', 'arn:aws:iam::765932874577:user/Other'),
        ):
            current = deepcopy(self.current)
            next(item for item in current if item['ParameterKey'] == name)['ParameterValue'] = value
            with self.subTest(name=name), self.assertRaises(owner.OwnerReleaseError):
                owner.owner_parameters(self.original['Parameters'], current)

    def test_processed_template_pins_all_ten_owner_logical_ids_and_types(self):
        owner.validate_owner_templates(self.original, self.processed)
        for change in ('extra', 'missing', 'version', 'condition', 'transform'):
            processed = deepcopy(self.processed)
            if change == 'extra':
                processed['Resources']['Unrelated'] = {'Type': 'AWS::IAM::Role',
                    'Condition': owner.OWNER_CONDITION}
            elif change == 'missing':
                del processed['Resources']['ThnProductionOwnerHumanOperatorRole']
            elif change == 'version':
                processed['Resources']['ThnProductionOwnerOperatorV2FunctionVersionDIFFERENT'] = \
                    processed['Resources'].pop('ThnProductionOwnerOperatorV2FunctionVersion70edfefcc3')
            elif change == 'condition':
                processed['Resources']['ThnProductionOwnerHumanOperatorRole']['Condition'] = 'Other'
            else:
                processed['Transform'] = ['AWS::Serverless-2016-10-31', 'AWS::LanguageExtensions']
            with self.subTest(change=change), self.assertRaises(owner.OwnerReleaseError):
                owner.validate_owner_templates(self.original, processed)

    def test_owner_trust_requires_exact_mfa_condition_and_private_function_url(self):
        owner.validate_owner_templates(self.original, self.processed)
        for target, mutate in (
            ('trust', lambda t: t['Resources']['ThnProductionOwnerHumanOperatorRole']
                ['Properties']['AssumeRolePolicyDocument']['Statement'][0]
                ['Condition']['NumericLessThanEquals'].update({'aws:MultiFactorAuthAge': '900'})),
            ('url', lambda t: t['Resources']['ThnProductionOwnerOperatorV2FunctionUrl']
                ['Properties'].update({'AuthType': 'NONE'})),
        ):
            original = deepcopy(self.original)
            mutate(original)
            with self.subTest(target=target), self.assertRaises(owner.OwnerReleaseError):
                owner.validate_owner_templates(original, self.processed)

    def test_inventory_accepts_exact_ten_additions_without_replacement(self):
        changes = [
            {'ResourceChange': {'Action': 'Add', 'LogicalResourceId': logical,
                'ResourceType': kind, 'Replacement': 'False'}}
            for logical, kind in owner.OWNER_RESOURCES.items()
        ]
        owner.validate_owner_inventory(changes, self.processed)
        for change in ('missing', 'extra', 'modify', 'replacement', 'type'):
            candidate = deepcopy(changes)
            if change == 'missing':
                candidate.pop()
            elif change == 'extra':
                candidate.append({'ResourceChange': {'Action': 'Add',
                    'LogicalResourceId': 'Unrelated', 'ResourceType': 'AWS::IAM::Policy',
                    'Replacement': 'False'}})
            elif change == 'modify':
                candidate[0]['ResourceChange']['Action'] = 'Modify'
            elif change == 'replacement':
                candidate[0]['ResourceChange']['Replacement'] = 'Conditional'
            else:
                candidate[0]['ResourceChange']['ResourceType'] = 'AWS::S3::Bucket'
            with self.subTest(change=change), self.assertRaises(owner.OwnerReleaseError):
                owner.validate_owner_inventory(candidate, self.processed)

    def test_sealed_review_requires_fresh_source_baseline_iam_and_inventory(self):
        changes = [{'ResourceChange': {'Action': 'Add', 'LogicalResourceId': name,
                    'ResourceType': kind, 'Replacement': 'False'}}
                   for name, kind in owner.OWNER_RESOURCES.items()]
        args = {'source_sha': 'a' * 40,
                'stack_id': 'arn:aws:cloudformation:us-east-1:765932874577:stack/'
                            'zoolanding-auth-admin-prod/11111111-1111-1111-1111-111111111111',
                'change_set_arn': 'arn:aws:cloudformation:us-east-1:765932874577:changeSet/'
                                  'thn-production-auth-owner-123/11111111-1111-1111-1111-111111111111',
                'created_at': 1000, 'baseline': {'resources': ['existing']},
                'original': self.original, 'processed': self.processed,
                'parameters': owner.owner_parameters(self.original['Parameters'], self.current),
                'identity': {'principal': 'exact'}, 'permissions': {'allowed': True},
                'changes': changes}
        record = owner.make_owner_review_record(**args)
        owner.verify_owner_review_record(record, approved_digest=record['digest'],
                                         now=1001, **{key: args[key] for key in
                                         ('source_sha', 'baseline', 'original', 'processed',
                                          'parameters', 'identity', 'permissions', 'changes')})
        for changed in ('source_sha', 'baseline', 'original', 'processed', 'parameters',
                        'identity', 'permissions', 'changes'):
            mutated = deepcopy(args)
            mutated[changed] = 'b' * 40 if changed == 'source_sha' else {'different': True}
            with self.subTest(changed=changed), self.assertRaises(owner.OwnerReleaseError):
                owner.verify_owner_review_record(record, approved_digest=record['digest'],
                    now=1001, **{key: mutated[key] for key in
                    ('source_sha', 'baseline', 'original', 'processed', 'parameters',
                     'identity', 'permissions', 'changes')})
        for now, digest in ((1000 + 86400, record['digest']), (1001, 'b' * 64)):
            with self.assertRaises(owner.OwnerReleaseError):
                owner.verify_owner_review_record(record, approved_digest=digest,
                    now=now, **{key: args[key] for key in
                    ('source_sha', 'baseline', 'original', 'processed', 'parameters',
                     'identity', 'permissions', 'changes')})

    def test_deploy_role_requires_all_fifteen_exact_read_decisions(self):
        stack_id = 'arn:aws:cloudformation:us-east-1:765932874577:stack/' \
                   'zoolanding-auth-admin-prod/11111111-1111-1111-1111-111111111111'
        class IAM:
            denied = False
            def __init__(self):
                self.calls = []
            def simulate_principal_policy(self, **request):
                self.calls.append(request)
                return {'EvaluationResults': [
                    {'EvalActionName': action,
                     'EvalResourceName': request['ResourceArns'][0],
                     'EvalDecision': 'implicitDeny' if self.denied else 'allowed',
                     'MissingContextValues': []}
                    for action in request['ActionNames']]}
        iam = IAM()
        proof = owner.prove_owner_deploy_reads(iam, stack_id)
        self.assertEqual(len(iam.calls), 7)
        self.assertEqual(sum(len(call['ActionNames']) for call in iam.calls), 15)
        self.assertEqual(len(proof), 7)
        self.assertTrue(all(call['PolicySourceArn'] ==
            'arn:aws:iam::765932874577:role/zoolanding-auth-admin-production-deploy'
            for call in iam.calls))
        iam.denied = True
        with self.assertRaises(owner.OwnerReleaseError):
            owner.prove_owner_deploy_reads(iam, stack_id)

    def test_historical_sam_version_row_still_covers_pinned_native_version(self):
        historical = {'resourceType': 'AWS::Lambda::Version',
            'logicalIds': ['ThnProductionOwnerOperatorV2FunctionVersionbb9bb6a892']}
        self.assertTrue(owner.is_owner_manifest_row(historical))
        self.assertFalse(owner.is_owner_manifest_row({'resourceType': 'AWS::Lambda::Version',
            'logicalIds': ['UnrelatedFunctionVersionbb9bb6a892']}))
        self.assertFalse(owner.is_owner_manifest_row({'resourceType': 'AWS::IAM::Role',
            'logicalIds': ['ThnProductionOwnerOperatorV2FunctionVersionbb9bb6a892']}))

    def test_change_set_request_reuses_deployed_template_and_only_three_values(self):
        stack_id = 'arn:aws:cloudformation:us-east-1:765932874577:stack/' \
                   'zoolanding-auth-admin-prod/11111111-1111-1111-1111-111111111111'
        current = {'stackId': stack_id, 'status': 'UPDATE_COMPLETE',
                   'terminationProtection': True,
                   'roleArn': 'arn:aws:iam::765932874577:role/'
                              'zoolanding-deployer-auth-admin-production-cfn-exec',
                   'parameters': self.current, 'tags': [{'Key': 'project', 'Value': 'thn'}],
                   'original': self.original, 'processed': self.processed,
                   'resources': [{'LogicalResourceId': f'Existing{i}',
                                  'PhysicalResourceId': f'existing-{i}'} for i in range(37)]}
        request = owner.owner_change_set_request(current, run_id='12345', attempt='1')
        self.assertEqual(request['StackName'], stack_id)
        self.assertTrue(request['UsePreviousTemplate'])
        self.assertNotIn('TemplateBody', request)
        self.assertNotIn('TemplateURL', request)
        self.assertEqual(request['Capabilities'], ['CAPABILITY_NAMED_IAM'])
        self.assertEqual(request['RoleARN'], current['roleArn'])
        self.assertEqual(request['Tags'], current['tags'])
        self.assertEqual(len([p for p in request['Parameters'] if 'ParameterValue' in p]), 3)
        self.assertIn({'ParameterKey': 'LegacySecret', 'UsePreviousValue': True},
                      request['Parameters'])
        for target, value in (('status', 'UPDATE_IN_PROGRESS'),
                              ('terminationProtection', False),
                              ('roleArn', 'arn:aws:iam::765932874577:role/Other'),
                              ('resources', current['resources'][:-1])):
            changed = deepcopy(current)
            changed[target] = value
            with self.subTest(target=target), self.assertRaises(owner.OwnerReleaseError):
                owner.owner_change_set_request(changed, run_id='12345', attempt='1')

    def test_postcheck_preserves_all_existing_physical_ids_and_closed_routes(self):
        before = {'stackId': 'arn:aws:cloudformation:us-east-1:765932874577:stack/'
                    'zoolanding-auth-admin-prod/11111111-1111-1111-1111-111111111111',
                  'status': 'UPDATE_COMPLETE', 'terminationProtection': True,
                  'roleArn': 'arn:aws:iam::765932874577:role/'
                             'zoolanding-deployer-auth-admin-production-cfn-exec',
                  'tags': [], 'parameters': self.current,
                  'original': self.original, 'processed': self.processed,
                  'resources': [{'LogicalResourceId': f'Existing{i}',
                                 'PhysicalResourceId': f'existing-{i}'} for i in range(37)]}
        after = deepcopy(before)
        for item in after['parameters']:
            name = item['ParameterKey']
            if name in owner.OVERRIDES:
                item['ParameterValue'] = owner.OVERRIDES[name]
        after['resources'].extend({'LogicalResourceId': name,
                                   'PhysicalResourceId': f'new-{index}',
                                   'ResourceType': kind}
                                  for index, (name, kind) in enumerate(owner.OWNER_RESOURCES.items()))
        owner.verify_owner_post(before, after)
        for target in ('physical', 'route', 'extra'):
            wrong = deepcopy(after)
            if target == 'physical':
                wrong['resources'][0]['PhysicalResourceId'] = 'replaced'
            elif target == 'route':
                next(p for p in wrong['parameters'] if
                     p['ParameterKey'] == 'EnableThnAuthAdminV2')['ParameterValue'] = 'true'
            else:
                wrong['resources'].append({'LogicalResourceId': 'Unrelated',
                                           'PhysicalResourceId': 'new-other'})
            with self.subTest(target=target), self.assertRaises(owner.OwnerReleaseError):
                owner.verify_owner_post(before, wrong)

    def test_preview_requires_same_templates_three_values_and_ten_additions(self):
        stack_id = 'arn:aws:cloudformation:us-east-1:765932874577:stack/' \
                   'zoolanding-auth-admin-prod/11111111-1111-1111-1111-111111111111'
        current = {'stackId': stack_id, 'parameters': self.current,
                   'original': self.original, 'processed': self.processed,
                   'roleArn': 'arn:aws:iam::765932874577:role/'
                              'zoolanding-deployer-auth-admin-production-cfn-exec'}
        expected = deepcopy(self.current)
        for item in expected:
            if item['ParameterKey'] in owner.OVERRIDES:
                item['ParameterValue'] = owner.OVERRIDES[item['ParameterKey']]
        preview = {'Status': 'CREATE_COMPLETE', 'ExecutionStatus': 'AVAILABLE',
                   'StackId': stack_id, 'RoleARN': current['roleArn'],
                   'Parameters': expected, 'Changes': [
                       {'Type': 'Resource', 'ResourceChange': {'Action': 'Add',
                        'LogicalResourceId': name, 'ResourceType': kind,
                        'Replacement': 'False'}}
                       for name, kind in owner.OWNER_RESOURCES.items()]}
        owner.validate_owner_preview(preview, current, self.original, self.processed)
        for target in ('template', 'parameter', 'inventory', 'stack'):
            changed = deepcopy(preview)
            original = deepcopy(self.original)
            if target == 'template':
                original['Resources']['Existing']['Type'] = 'AWS::S3::Bucket'
            elif target == 'parameter':
                changed['Parameters'][0]['ParameterValue'] = 'false'
            elif target == 'inventory':
                changed['Changes'][0]['ResourceChange']['Action'] = 'Modify'
            else:
                changed['StackId'] += 'other'
            with self.subTest(target=target), self.assertRaises(owner.OwnerReleaseError):
                owner.validate_owner_preview(changed, current, original, self.processed)

    def test_review_preflights_before_write_and_cleans_unexpected_preview(self):
        stack_id = 'arn:aws:cloudformation:us-east-1:765932874577:stack/' \
                   'zoolanding-auth-admin-prod/11111111-1111-1111-1111-111111111111'
        change_set_arn = 'arn:aws:cloudformation:us-east-1:765932874577:changeSet/' \
                         'thn-production-auth-owner-12345-1/11111111-1111-1111-1111-111111111111'
        current = {'stackId': stack_id, 'status': 'UPDATE_COMPLETE',
                   'terminationProtection': True,
                   'roleArn': 'arn:aws:iam::765932874577:role/'
                              'zoolanding-deployer-auth-admin-production-cfn-exec',
                   'tags': [], 'parameters': self.current,
                   'original': self.original, 'processed': self.processed,
                   'resources': [{'LogicalResourceId': f'Existing{i}',
                                  'PhysicalResourceId': f'existing-{i}'} for i in range(37)]}
        values = deepcopy(self.current)
        for item in values:
            if item['ParameterKey'] in owner.OVERRIDES:
                item['ParameterValue'] = owner.OVERRIDES[item['ParameterKey']]
        preview = {'Status': 'CREATE_COMPLETE', 'ExecutionStatus': 'AVAILABLE',
                   'StackId': stack_id, 'Parameters': values,
                   'Changes': [{'ResourceChange': {'Action': 'Add',
                       'LogicalResourceId': name, 'ResourceType': kind,
                       'Replacement': 'False'}} for name, kind in owner.OWNER_RESOURCES.items()]}
        class CF:
            def __init__(self):
                self.calls = []
                self.preview = deepcopy(preview)
            def create_change_set(self, **request):
                self.calls.append('create')
                return {'Id': change_set_arn}
            def get_waiter(self, name):
                self.calls.append('waiter')
                class Waiter:
                    def wait(self, **request):
                        pass
                return Waiter()
            def describe_change_set(self, **request):
                self.calls.append('describe')
                return self.preview
            def get_template(self, **request):
                self.calls.append('template')
                return {'TemplateBody': current['original'] if
                    request['TemplateStage'] == 'Original' else current['processed']}
            def delete_change_set(self, **request):
                self.calls.append('delete')
        cf = CF()
        denied = lambda: (_ for _ in ()).throw(owner.OwnerReleaseError('denied'))
        with self.assertRaises(owner.OwnerReleaseError):
            owner.run_owner_review(cf, preflight=denied, source_sha='a' * 40,
                                   run_id='12345', attempt='1', created_at=1000)
        self.assertEqual(cf.calls, [])
        cf = CF()
        preflight = lambda: (current, {'principal': 'exact'}, {'allowed': True})
        record = owner.run_owner_review(cf, preflight=preflight,
            source_sha='a' * 40, run_id='12345', attempt='1', created_at=1000)
        self.assertEqual(record['changeSetArn'], change_set_arn)
        self.assertEqual(record['changes'].__len__(), 10)
        self.assertNotIn('delete', cf.calls)
        cf = CF()
        cf.preview['Changes'][0]['ResourceChange']['Action'] = 'Modify'
        with self.assertRaises(owner.OwnerReleaseError):
            owner.run_owner_review(cf, preflight=preflight,
                source_sha='a' * 40, run_id='12345', attempt='1', created_at=1000)
        self.assertEqual(cf.calls[-1], 'delete')

    def test_execute_checks_digest_and_full_preview_before_mutation(self):
        stack_id = 'arn:aws:cloudformation:us-east-1:765932874577:stack/' \
                   'zoolanding-auth-admin-prod/11111111-1111-1111-1111-111111111111'
        change_set_arn = 'arn:aws:cloudformation:us-east-1:765932874577:changeSet/' \
                         'thn-production-auth-owner-12345-1/11111111-1111-1111-1111-111111111111'
        before = {'stackId': stack_id, 'status': 'UPDATE_COMPLETE',
                  'terminationProtection': True,
                  'roleArn': 'arn:aws:iam::765932874577:role/'
                             'zoolanding-deployer-auth-admin-production-cfn-exec',
                  'tags': [], 'parameters': self.current,
                  'original': self.original, 'processed': self.processed,
                  'resources': [{'LogicalResourceId': f'Existing{i}',
                                 'PhysicalResourceId': f'existing-{i}'} for i in range(37)]}
        after = deepcopy(before)
        for item in after['parameters']:
            if item['ParameterKey'] in owner.OVERRIDES:
                item['ParameterValue'] = owner.OVERRIDES[item['ParameterKey']]
        after['resources'].extend({'LogicalResourceId': name,
                                   'PhysicalResourceId': f'new-{index}',
                                   'ResourceType': kind}
                                  for index, (name, kind) in enumerate(owner.OWNER_RESOURCES.items()))
        changes = [{'ResourceChange': {'Action': 'Add', 'LogicalResourceId': name,
                    'ResourceType': kind, 'Replacement': 'False'}}
                   for name, kind in owner.OWNER_RESOURCES.items()]
        preview = {'Status': 'CREATE_COMPLETE', 'ExecutionStatus': 'AVAILABLE',
                   'StackId': stack_id, 'Parameters': after['parameters'],
                   'Changes': changes}
        record = owner.make_owner_review_record(source_sha='a' * 40,
            stack_id=stack_id, change_set_arn=change_set_arn, created_at=1000,
            baseline=before, original=self.original, processed=self.processed,
            parameters=preview['Parameters'], identity={'principal': 'exact'},
            permissions={'allowed': True}, changes=changes)
        class CF:
            def __init__(self):
                self.preview = deepcopy(preview)
                self.executed = []
            def describe_change_set(self, **request):
                return self.preview
            def get_template(self, **request):
                return {'TemplateBody': before['original'] if
                    request['TemplateStage'] == 'Original' else before['processed']}
            def execute_change_set(self, **request):
                self.executed.append(request)
            def get_waiter(self, name):
                class Waiter:
                    def wait(self, **request):
                        pass
                return Waiter()
        cf = CF()
        kwargs = {'record': record, 'approved_digest': record['digest'],
                  'source_sha': 'a' * 40, 'now': 1001,
                  'preflight': lambda: (before, {'principal': 'exact'}, {'allowed': True}),
                  'postflight': lambda: after,
                  'authority_check': lambda: None,
                  'verify_owner_runtime': lambda: None}
        owner.run_owner_execute(cf, **kwargs)
        self.assertEqual(cf.executed, [{'ChangeSetName': change_set_arn,
                                        'StackName': stack_id}])
        cf = CF()
        def failed_update(_):
            class Waiter:
                def wait(self, **request):
                    raise RuntimeError('stack update failed')
            return Waiter()
        cf.get_waiter = failed_update
        with self.assertRaises(RuntimeError):
            owner.run_owner_execute(cf, **kwargs)
        self.assertEqual(len(cf.executed), 1)
        for changed in ('digest', 'baseline', 'inventory'):
            cf = CF()
            attempt = dict(kwargs)
            if changed == 'digest':
                attempt['approved_digest'] = 'b' * 64
            elif changed == 'baseline':
                wrong = deepcopy(before)
                wrong['resources'][0]['PhysicalResourceId'] = 'replaced'
                attempt['preflight'] = lambda: (wrong, {'principal': 'exact'},
                                               {'allowed': True})
            else:
                cf.preview['Changes'].pop()
            with self.subTest(changed=changed), self.assertRaises(owner.OwnerReleaseError):
                owner.run_owner_execute(cf, **attempt)
            self.assertEqual(cf.executed, [])


if __name__ == '__main__':
    unittest.main()
