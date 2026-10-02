"""Read-only preflight gates for the manual owner-operator workflow."""
import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path
from types import SimpleNamespace

from tools import run_thn_production_owner_parameter_release as driver
from tools import thn_production_owner_parameter_release as owner


class OwnerDriverPreflightTests(unittest.TestCase):
    def test_owner_package_must_match_deployed_version_and_be_readable(self):
        source = {'Bucket': 'zlp-thn-production-releases-765932874577-us-east-1',
                  'Key': 'thn/production/auth/source/packages/object',
                  'Version': 'version-1'}
        original = {'Resources': {'ThnProductionOwnerOperatorV2Function': {
            'Properties': {'CodeUri': source}}}}
        processed = {'Resources': {'ThnProductionOwnerOperatorV2Function': {
            'Properties': {'Code': {'S3Bucket': source['Bucket'],
                                    'S3Key': source['Key'],
                                    'S3ObjectVersion': source['Version']}}}}}
        class IAM:
            allowed = True
            def simulate_principal_policy(self, **request):
                return {'EvaluationResults': [{
                    'EvalActionName': 's3:getobjectversion',
                    'EvalResourceName': request['ResourceArns'][0],
                    'EvalDecision': 'allowed' if self.allowed else 'implicitDeny',
                    'MissingContextValues': []}]}
        class S3:
            def head_object(self, **request):
                return {'VersionId': 'version-1', 'ContentLength': 100,
                        'ServerSideEncryption': 'AES256'}
        iam, s3 = IAM(), S3()
        session = SimpleNamespace(client=lambda name: {'iam': iam, 's3': s3}[name])
        self.assertEqual(driver.owner_package_state(session, original, processed)
                         ['contentLength'], 100)
        iam.allowed = False
        with self.assertRaises(owner.OwnerReleaseError):
            driver.owner_package_state(session, original, processed)
        iam.allowed = True
        processed['Resources']['ThnProductionOwnerOperatorV2Function']['Properties'][
            'Code']['S3ObjectVersion'] = 'other'
        with self.assertRaises(owner.OwnerReleaseError):
            driver.owner_package_state(session, original, processed)

    def test_runtime_verifies_resolved_human_principal_and_closed_group(self):
        trust = {'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Action': 'sts:AssumeRole',
            'Principal': {'AWS': {'Ref': 'ThnProductionOwnerHumanPrincipalArn'}},
            'Condition': {'Bool': {'aws:MultiFactorAuthPresent': 'true'},
                          'NumericLessThanEquals': {'aws:MultiFactorAuthAge': '300'}},
        }]}
        actual = __import__('copy').deepcopy(trust)
        actual['Statement'][0]['Principal'] = {'AWS': owner.HUMAN_PRINCIPAL}
        class IAM:
            def get_role(self, **request):
                return {'Role': {'Arn': driver.HUMAN_ROLE_ARN,
                                 'AssumeRolePolicyDocument': actual}}
            def list_role_policies(self, **request):
                return {'PolicyNames': ['OperateExactThnOwnerV2']}
            def list_attached_role_policies(self, **request):
                return {'AttachedPolicies': []}
            def get_role_policy(self, **request):
                arn = ('arn:aws:lambda:us-east-1:765932874577:function:'
                       'zoolanding-auth-admin-prod-ThnProductionOwnerOperatorV2:production')
                return {'PolicyDocument': {'Version': '2012-10-17', 'Statement': [
                    {'Sid': 'ReadExactThnOwnerMediatorUrl', 'Effect': 'Allow',
                     'Action': ['lambda:GetFunctionUrlConfig'], 'Resource': arn},
                    {'Sid': 'InvokeExactThnOwnerMediatorUrl', 'Effect': 'Allow',
                     'Action': ['lambda:InvokeFunctionUrl'], 'Resource': arn,
                     'Condition': {'StringEquals': {
                         'lambda:FunctionUrlAuthType': 'AWS_IAM'}}},
                    {'Sid': 'InvokeExactThnOwnerMediatorOnlyViaUrl', 'Effect': 'Allow',
                     'Action': ['lambda:InvokeFunction'], 'Resource': arn,
                     'Condition': {'Bool': {
                         'lambda:InvokedViaFunctionUrl': 'true'}}},
                ]}}
        class Lambda:
            def get_alias(self, **request):
                return {'Name': 'production', 'FunctionVersion': '1'}
            def get_function_url_config(self, **request):
                return {'AuthType': 'AWS_IAM', 'InvokeMode': 'BUFFERED',
                        'FunctionUrl': 'https://abc123.lambda-url.us-east-1.on.aws/'}
        class Cognito:
            def list_users_in_group(self, **request):
                return {'Users': []}
        clients = {'iam': IAM(), 'lambda': Lambda(), 'cognito-idp': Cognito()}
        session = SimpleNamespace(client=lambda name: clients[name])
        post = {'original': {'Resources': {'ThnProductionOwnerHumanOperatorRole': {
            'Properties': {'AssumeRolePolicyDocument': trust}}}}, 'processed': {}}
        with patch.object(driver, 'capture_owner_post', return_value=post), \
             patch.object(owner, 'assert_deployed_template_fingerprints'):
            self.assertTrue(driver.verify_owner_runtime(session))
            actual['Statement'][0]['Principal'] = {'AWS': 'arn:aws:iam::765932874577:user/other'}
            with self.assertRaises(owner.OwnerReleaseError):
                driver.verify_owner_runtime(session)

    def test_validate_requires_exact_main_source_without_aws(self):
        with patch.object(driver, 'source_selection',
                          return_value={'sourceSha': 'a' * 40}) as selected:
            self.assertEqual(driver.main(['validate', '--source-sha', 'a' * 40]), 0)
            selected.assert_called_once_with('a' * 40)
            self.assertEqual(driver.main(['validate', '--source-sha', 'bad']), 2)

    def test_review_writes_only_sanitized_record_after_preflight(self):
        record = {'digest': 'b' * 64, 'sourceSha': 'a' * 40,
                  'stackId': 'arn:aws:cloudformation:us-east-1:765932874577:stack/'
                             'zoolanding-auth-admin-prod/11111111-1111-1111-1111-111111111111',
                  'changeSetArn': 'arn:aws:cloudformation:us-east-1:765932874577:'
                                  'changeSet/thn-production-auth-owner-12345-1/id',
                  'changes': [], 'expiresAt': 86400}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'review.json'
            with patch.object(driver, 'source_selection',
                              return_value={'sourceSha': 'a' * 40}), \
                 patch.object(driver, 'make_session',
                              return_value=SimpleNamespace(client=lambda _: object())), \
                 patch.object(owner, 'run_owner_review', return_value=record) as run, \
                 patch.dict('os.environ', {
                     'AWS_ROLE_ARN': 'arn:aws:iam::765932874577:role/'
                                     'zoolanding-auth-admin-production-deploy',
                     'GITHUB_RUN_ID': '12345', 'GITHUB_RUN_ATTEMPT': '1'}):
                self.assertEqual(driver.main(['review', '--source-sha', 'a' * 40,
                                               '--record', str(path)]), 0)
                self.assertEqual(path.read_text(encoding='utf-8').strip()[0], '{')
                self.assertEqual(__import__('json').loads(path.read_text()), record)
                self.assertTrue(callable(run.call_args.kwargs['preflight']))

    def test_execute_requires_review_run_and_digest_before_aws(self):
        record = {'digest': 'b' * 64, 'sourceSha': 'a' * 40,
                  'stackId': 'arn:aws:cloudformation:us-east-1:765932874577:stack/'
                             'zoolanding-auth-admin-prod/11111111-1111-1111-1111-111111111111',
                  'changeSetArn': 'arn:aws:cloudformation:us-east-1:765932874577:'
                                  'changeSet/thn-production-auth-owner-12345-1/id'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'review.json'
            path.write_text(__import__('json').dumps(record), encoding='utf-8')
            with patch.object(driver, 'source_selection',
                              return_value={'sourceSha': 'a' * 40}), \
                 patch.object(driver, 'make_session',
                              return_value=SimpleNamespace(client=lambda _: object())) as session, \
                 patch.object(owner, 'run_owner_execute',
                              return_value={'executed': True, 'digest': 'b' * 64}) as run, \
                 patch.dict('os.environ', {'AWS_ROLE_ARN':
                     'arn:aws:iam::765932874577:role/'
                     'zoolanding-auth-admin-production-deploy'}):
                self.assertEqual(driver.main(['execute', '--source-sha', 'a' * 40,
                    '--review-run-id', '12345', '--approved-digest', 'b' * 64,
                    '--record', str(path)]), 0)
                self.assertTrue(callable(run.call_args.kwargs['preflight']))
                session.reset_mock()
                run.reset_mock()
                self.assertEqual(driver.main(['execute', '--source-sha', 'a' * 40,
                    '--review-run-id', '99999', '--approved-digest', 'b' * 64,
                    '--record', str(path)]), 2)
                session.assert_not_called()
                run.assert_not_called()

    def test_read_only_preflight_rejects_competing_change_set_and_missing_mfa(self):
        stack_id = 'arn:aws:cloudformation:us-east-1:765932874577:stack/' \
                   'zoolanding-auth-admin-prod/11111111-1111-1111-1111-111111111111'
        state = {'stackId': stack_id, 'original': {}, 'processed': {},
                 'resources': [], 'parameters': []}
        class CF:
            change_status = None
            def list_change_sets(self, **request):
                return {'Summaries': [{'ChangeSetId': 'other',
                         'Status': self.change_status[0],
                         'ExecutionStatus': self.change_status[1]}]
                         if self.change_status else []}
        class IAM:
            mfa = True
            def get_role(self, **request):
                return {'Role': {'Arn': 'arn:aws:iam::765932874577:role/'
                    'zoolanding-auth-admin-production-deploy',
                    'RoleId': 'role-id', 'AssumeRolePolicyDocument': {'Statement': []}}}
            def list_mfa_devices(self, **request):
                return {'MFADevices': [{'SerialNumber': 'hidden'}] if self.mfa else []}
            def simulate_principal_policy(self, **request):
                return {'EvaluationResults': [{'EvalActionName': 'sts:assumerole',
                    'EvalResourceName': request['ResourceArns'][0],
                    'EvalDecision': 'allowed', 'MissingContextValues': []}]}
        class Cognito:
            def list_users_in_group(self, **request):
                return {'Users': []}
        class STS:
            def get_caller_identity(self):
                return {'Account': '765932874577',
                    'Arn': 'arn:aws:sts::765932874577:assumed-role/'
                           'zoolanding-auth-admin-production-deploy/run'}
        class Session:
            region_name = 'us-east-1'
            def __init__(self):
                self.cf, self.iam = CF(), IAM()
            def client(self, name):
                return {'cloudformation': self.cf, 'iam': self.iam,
                        'cognito-idp': Cognito(), 'sts': STS()}[name]
        session = Session()
        with patch.object(driver.release, 'snapshot', return_value=state), \
             patch.object(owner, 'owner_change_set_request'), \
             patch.object(owner, 'assert_deployed_template_fingerprints'), \
             patch.object(owner, 'prove_owner_deploy_reads', return_value=[{'allowed': True}]), \
             patch.object(owner, 'prove_owner_native_permissions',
                          return_value={'schemaHashes': {}, 'requests': []}), \
             patch.object(driver, 'owner_package_state', return_value={'versionId': 'v'}), \
             patch.object(driver, 'validate_github_trust'):
            result = driver.capture_owner_preflight(session)
            self.assertEqual(result[0]['stackId'], stack_id)
            for status in (('CREATE_COMPLETE', 'AVAILABLE'),
                           ('CREATE_PENDING', 'UNAVAILABLE'),
                           ('CREATE_IN_PROGRESS', 'UNAVAILABLE')):
                session.cf.change_status = status
                with self.subTest(status=status), self.assertRaises(owner.OwnerReleaseError):
                    driver.capture_owner_preflight(session)
            session.cf.change_status = ('CREATE_COMPLETE', 'AVAILABLE')
            self.assertEqual(driver.capture_owner_preflight(
                session, allowed_change_set_arn='other')[0]['stackId'], stack_id)
            session.cf.change_status = ('CREATE_IN_PROGRESS', 'UNAVAILABLE')
            with self.assertRaises(owner.OwnerReleaseError):
                driver.capture_owner_preflight(session,
                    allowed_change_set_arn='other')
            session.cf.change_status = None
            session.iam.mfa = False
            with self.assertRaises(owner.OwnerReleaseError):
                driver.capture_owner_preflight(session)


if __name__ == '__main__':
    unittest.main()
