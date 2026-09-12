"""Synthetic, offline QA lifecycle tests through the real IAM mediator."""
import copy
import hashlib
import importlib
import json
import pathlib
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

import auth_admin_current_user_v2 as current
import auth_admin_owner_operator_v2 as mediator
from test_auth_admin_owner_operator_v2 import function_url_event
from test_provision_thn_owner import (
    RecordingCognitoClient, RecordingSession, TEMPORARY_PASSWORD,
)
from tools import build_lambda_artifact as builder
from tools import check_lambda_artifacts as checker
from tools import provision_thn_owner as owner

ROOT = pathlib.Path(__file__).resolve().parents[1]
QA_EMAIL = 'qa@example.test'
QA_SUBJECT = 'qa-subject-synthetic'
QA_USERNAME = 'qa-provider-synthetic'
QA_KEY = 'QA#qa'


class MemoryDynamo:
    """Only the exact existing Get/Put/Update and transaction IAM primitives."""
    def __init__(self):
        self.items = {}
        self.calls = []
        self.fail_audit_phase = None
        self.lose_transaction_response = False
        self.before_transaction = None

    def get_item(self, **request):
        self.calls.append(('get_item', copy.deepcopy(request)))
        assert request['ConsistentRead'] is True
        key = current.unmarshal_item(request['Key'])
        item = self.items.get((request['TableName'], key['pk'], key['sk']))
        return {'Item': current.marshal_item(item)} if item else {}

    def _write(self, kind, request):
        table = request['TableName']
        raw = current.unmarshal_item(request['Item'] if kind == 'Put' else request['Key'])
        key = (table, raw['pk'], raw['sk'])
        names = request['ExpressionAttributeNames']
        values = current.unmarshal_item(request.get('ExpressionAttributeValues', {}))
        old = self.items.get(key)
        for condition in request['ConditionExpression'].split(' AND '):
            if condition.startswith('attribute_not_exists('):
                field = names[condition[len('attribute_not_exists('):-1]]
                valid = old is None or field not in old
            else:
                field, value = condition.split(' = ')
                valid = old is not None and old.get(names[field]) == values[value]
            if not valid:
                raise RuntimeError('synthetic conditional conflict')
        if kind == 'Put':
            self.items[key] = copy.deepcopy(raw)
        else:
            for assignment in request['UpdateExpression'].removeprefix('SET ').split(', '):
                field, value = assignment.split(' = ')
                old[names[field]] = values[value]
        return {'Attributes': current.marshal_item(self.items[key])}

    def put_item(self, **request):
        self.calls.append(('put_item', copy.deepcopy(request)))
        assert request['TableName'] == owner.APPROVED_AUDIT_TABLE_NAME
        item = current.unmarshal_item(request['Item'])
        if item['phase'] == self.fail_audit_phase:
            raise RuntimeError('synthetic audit failure')
        return self._write('Put', request)

    def update_item(self, **request):
        self.calls.append(('update_item', copy.deepcopy(request)))
        assert request['TableName'] == current.APPROVED_TABLE_NAME
        return self._write('Update', request)

    def transact_write_items(self, **request):
        self.calls.append(('transact_write_items', copy.deepcopy(request)))
        if self.before_transaction:
            action, self.before_transaction = self.before_transaction, None
            action()
        snapshot = copy.deepcopy(self.items)
        try:
            for operation in request['TransactItems']:
                assert len(operation) == 1
                kind, value = next(iter(operation.items()))
                assert kind in {'Put', 'Update'}  # no added ConditionCheckItem IAM
                assert value['TableName'] == current.APPROVED_TABLE_NAME
                self._write(kind, value)
        except Exception:
            self.items = snapshot
            raise
        if self.lose_transaction_response:
            self.lose_transaction_response = False
            raise RuntimeError('synthetic response loss after commit')
        return {}

    def state(self):
        return self.items[(current.APPROVED_TABLE_NAME, current.APPROVED_PARTITION_KEY, 'SUBJECT#' + QA_SUBJECT)]

    def reservation(self):
        return self.items[(current.APPROVED_TABLE_NAME, current.APPROVED_PARTITION_KEY, QA_KEY)]


class Cognito(RecordingCognitoClient):
    def __init__(self):
        super().__init__(email=QA_EMAIL, subject=QA_SUBJECT, provider_username=QA_USERNAME,
                         user_exists_before_create=False, user_groups=[], users_in_group=[])
        self.enabled = True
        self.lose_response_for = None

    def admin_get_user(self, **request):
        return {**super().admin_get_user(**request), 'Enabled': self.enabled}

    def admin_enable_user(self, **request):
        super().admin_enable_user(**request)
        self.enabled = True
        if self.lose_response_for == 'enable':
            raise RuntimeError('synthetic enable response lost')
        return {}

    def admin_disable_user(self, **request):
        super().admin_disable_user(**request)
        self.enabled = False
        return {}

    def admin_remove_user_from_group(self, **request):
        super().admin_remove_user_from_group(**request)
        if self.lose_response_for == 'remove':
            raise RuntimeError('synthetic remove response lost')
        return {}


class Session(RecordingSession):
    def __init__(self):
        super().__init__(cognito=Cognito())
        self.dynamodb = MemoryDynamo()

    def client(self, name):
        if name == 'dynamodb':
            self.client_names.append(name)
            return self.dynamodb
        return super().client(name)


class QaOperatorTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()

    def call(self, operation, *, target=mediator, **extra):
        payload = {'contractVersion': 1, 'operation': operation, 'username': QA_EMAIL}
        if operation in {'qa-create', 'qa-reset'}:
            payload['temporaryPassword'] = TEMPORARY_PASSWORD
        payload.update(extra)
        with patch.object(target, '_new_session', return_value=self.session), patch.object(
            target.owner, 'require_named_operator'
        ):
            return target.lambda_handler(function_url_event(payload), None)

    def success(self, operation):
        response = self.call(operation)
        self.assertEqual(response['statusCode'], 200)
        result = json.loads(response['body'])
        self.assertEqual(set(result), {'ok', 'operation', 'accountPurpose', 'sessionVersion', 'enabled'})
        self.assertEqual(result['accountPurpose'], 'qa')
        self.assertEqual(result['operation'], operation)
        self.assertNotIn(QA_EMAIL, response['body'])
        self.assertNotIn(QA_SUBJECT, response['body'])
        return result

    def test_qa_create_is_dispatched_with_transactional_disabled_state(self):
        result = self.success('qa-create')
        self.assertFalse(result['enabled'])
        self.assertEqual(result['sessionVersion'], 1)
        self.assertFalse(self.session.cognito.enabled)
        self.assertFalse(self.session.dynamodb.reservation()['retired'])
        self.assertFalse(any(key[2] == current.APPROVED_OWNER_BINDING_SORT_KEY for key in self.session.dynamodb.items))
        self.assertEqual(len([c for c in self.session.dynamodb.calls if c[0] == 'transact_write_items']), 1)

    def test_qa_enable_then_disable_is_terminal_and_retains_state(self):
        self.success('qa-create')
        self.assertTrue(self.success('qa-enable')['enabled'])
        self.assertEqual(self.session.dynamodb.state()['sessionVersion'], 2)
        result = self.success('qa-disable')
        self.assertFalse(result['enabled'])
        self.assertEqual(result['sessionVersion'], 3)
        self.assertTrue(self.session.dynamodb.reservation()['retired'])
        self.assertTrue(self.session.cognito.user_exists)
        self.assertFalse(self.session.cognito.enabled)
        self.assertEqual(self.session.cognito.user_groups, [])
        self.assertEqual(self.success('qa-disable'), result)
        for operation in ('qa-create', 'qa-enable'):
            with self.assertRaises(mediator.OwnerMediatorFailure):
                self.call(operation)

    def test_owner_binding_denies_qa_before_provider_mutation_even_if_malformed(self):
        store = self.session.dynamodb
        key = (current.APPROVED_TABLE_NAME, current.APPROVED_PARTITION_KEY, current.APPROVED_OWNER_BINDING_SORT_KEY)
        store.items[key] = {'pk': key[1], 'sk': key[2], 'unexpected': 'closed'}
        for operation in ('qa-create', 'qa-enable'):
            with self.assertRaises(mediator.OwnerMediatorFailure):
                self.call(operation)
        self.assertFalse(any(name.startswith('admin_') for name, _ in self.session.cognito.calls))

    def test_browser_scope_purpose_unknown_operations_rejected_before_session(self):
        for extra in ({'accountPurpose': 'qa'}, {'scope': {}}, {'subject': QA_SUBJECT},
                      {'environment': 'test'}, {'operation': 'qa-delete'}, {'operation': []}):
            with self.subTest(fields=list(extra)), patch.object(mediator, '_new_session') as factory:
                payload = {'contractVersion': 1, 'operation': 'qa-enable', 'username': QA_EMAIL, **extra}
                response = mediator.lambda_handler(function_url_event(payload), None)
                self.assertEqual(response['statusCode'], 400)
                factory.assert_not_called()

    def test_audit_intent_failure_has_zero_provider_writes(self):
        self.session.dynamodb.fail_audit_phase = 'intent'
        with self.assertRaises(mediator.OwnerMediatorFailure):
            self.call('qa-create')
        self.assertFalse(any(name.startswith('admin_') for name, _ in self.session.cognito.calls))

    def test_create_committed_transaction_response_loss_reconciles_exact_initial_state(self):
        self.session.dynamodb.lose_transaction_response = True
        self.success('qa-create')
        self.success('qa-create')
        self.assertEqual(self.session.dynamodb.state()['sessionVersion'], 1)

    def test_disable_committed_transaction_response_loss_is_closed_and_retryable(self):
        self.success('qa-create')
        self.success('qa-enable')
        self.session.dynamodb.lose_transaction_response = True
        self.success('qa-disable')
        self.assertFalse(self.session.dynamodb.state()['enabled'])
        self.assertEqual(self.success('qa-disable')['sessionVersion'], 3)

    def test_disable_provider_failure_stays_retired_and_retry_finishes_group_removal(self):
        self.success('qa-create')
        self.success('qa-enable')
        self.session.cognito.provider_error = 'admin_user_global_sign_out'
        with self.assertRaises(mediator.OwnerMediatorFailure):
            self.call('qa-disable')
        self.assertFalse(self.session.dynamodb.state()['enabled'])
        self.assertTrue(self.session.dynamodb.reservation()['retired'])
        self.assertFalse(self.session.cognito.enabled)
        self.session.cognito.provider_error = None
        self.success('qa-disable')
        self.assertEqual(self.session.cognito.user_groups, [])

    def test_revocation_precedes_resource_discovery_and_provider_identity_reads(self):
        for operation in ('qa-disable', 'qa-reset'):
            for failure in ('discovery', 'identity'):
                with self.subTest(operation=operation, failure=failure):
                    self.setUp()
                    self.success('qa-create')
                    self.success('qa-enable')
                    before_subjects = {key for key in self.session.dynamodb.items if key[2].startswith('SUBJECT#')}
                    failing_target = (patch.object(owner, 'discover_dedicated_resources', side_effect=RuntimeError('synthetic discovery failure'))
                        if failure == 'discovery' else patch.object(self.session.cognito, 'admin_get_user', side_effect=RuntimeError('synthetic identity failure')))
                    with failing_target, self.assertRaises(mediator.OwnerMediatorFailure):
                        self.call(operation)
                    self.assertFalse(self.session.dynamodb.state()['enabled'])
                    self.assertEqual(self.session.dynamodb.state()['sessionVersion'], 3)
                    self.assertEqual(self.session.dynamodb.reservation()['retired'], operation == 'qa-disable')
                    self.assertEqual(self.session.dynamodb.reservation()['resetPending'], operation == 'qa-reset')
                    self.success(operation)
                    self.assertFalse(self.session.dynamodb.state()['enabled'])
                    self.assertFalse(self.session.cognito.enabled)
                    self.assertEqual({key for key in self.session.dynamodb.items if key[2].startswith('SUBJECT#')}, before_subjects)
                    self.assertFalse(any(key[2] == current.APPROVED_OWNER_BINDING_SORT_KEY for key in self.session.dynamodb.items))

    def test_owner_cli_and_template_bytes_are_frozen(self):
        expected = {'tools/provision_thn_owner.py': '6347b78e06dedcab2c537940b151c20b5c7b4560cf51900e8851c92aa5dbd64a',
                    'template.yaml': '3cc898ee2604b36585f3cd5ffa9812897e3ccedb6a8124276f47637a5398bd8d'}
        # Normalize git checkout line endings; evidence records exact local bytes separately.
        for path, digest in expected.items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes().replace(b'\r\n', b'\n')).hexdigest(), digest)

    def test_reset_is_nonterminal_disabled_versioned_and_reenables_only_after_provider_completion(self):
        self.success('qa-create')
        self.success('qa-enable')
        reset = self.success('qa-reset')
        self.assertFalse(reset['enabled'])
        self.assertEqual(reset['sessionVersion'], 3)
        self.assertFalse(self.session.dynamodb.reservation()['retired'])
        self.assertFalse(self.session.cognito.enabled)
        self.assertIn('admin_delete_software_token', [name for name, _ in self.session.cognito.calls])
        self.assertEqual(self.success('qa-enable')['sessionVersion'], 4)

    def test_failed_reset_cannot_be_reenabled_until_reset_retry_completes(self):
        self.success('qa-create')
        self.success('qa-enable')
        self.session.cognito.provider_error = 'admin_delete_software_token'
        with self.assertRaises(mediator.OwnerMediatorFailure):
            self.call('qa-reset')
        self.assertFalse(self.session.dynamodb.state()['enabled'])
        self.assertTrue(self.session.dynamodb.reservation()['resetPending'])
        with self.assertRaises(mediator.OwnerMediatorFailure):
            self.call('qa-enable')
        self.session.cognito.provider_error = None
        self.success('qa-reset')
        self.success('qa-enable')

    def test_only_owner_artifact_admits_the_new_qa_dispatch(self):
        self.assertIn('auth_admin_qa_operator_v2.py', builder.SOURCE_ALLOWLIST['ThnAuthAdminV2OwnerOperatorFunction'])
        for target in builder.SOURCE_ALLOWLIST:
            with tempfile.TemporaryDirectory() as directory:
                builder.build_artifact(target, directory, install_dependencies=False)
                checker.validate_artifact(target, directory)
                if target != 'ThnAuthAdminV2OwnerOperatorFunction':
                    (pathlib.Path(directory) / 'auth_admin_qa_operator_v2.py').write_text('# extra', encoding='utf-8')
                    with self.assertRaises(checker.ArtifactValidationError):
                        checker.validate_artifact(target, directory)

    def test_failed_completed_enable_audit_does_not_leave_qa_active(self):
        self.success('qa-create')
        self.session.dynamodb.fail_audit_phase = 'completed'
        with self.assertRaises(mediator.OwnerMediatorFailure):
            self.call('qa-enable')
        self.assertFalse(self.session.dynamodb.state()['enabled'])
        self.assertTrue(self.session.dynamodb.reservation()['retired'])
        self.assertFalse(self.session.cognito.enabled)

    def test_qa_subject_purpose_and_scope_drift_never_enables_a_different_identity(self):
        for key, value in (('subject','other-subject'), ('accountPurpose','client-owner'),
                           ('scope',{'environment':'prod'}), ('accountHash','0'*64)):
            with self.subTest(field=key):
                self.setUp()
                self.success('qa-create')
                self.session.dynamodb.reservation()[key] = value
                before = len(self.session.cognito.calls)
                with self.assertRaises(mediator.OwnerMediatorFailure):
                    self.call('qa-enable')
                self.assertFalse(any(name in {'admin_enable_user','admin_add_user_to_group'}
                                     for name, _ in self.session.cognito.calls[before:]))

    def test_ambiguous_provider_create_is_disabled_then_retryable_without_second_account(self):
        self.session.cognito.create_commits_then_raises = True
        with self.assertRaises(mediator.OwnerMediatorFailure):
            self.call('qa-create')
        self.assertFalse(self.session.cognito.enabled)
        self.session.cognito.create_commits_then_raises = False
        self.success('qa-create')
        self.assertEqual(sum(name == 'admin_create_user' for name,_ in self.session.cognito.calls), 1)

    def test_ambiguous_enable_is_retired_and_disable_retry_finishes(self):
        self.success('qa-create')
        self.session.cognito.lose_response_for = 'enable'
        with self.assertRaises(mediator.OwnerMediatorFailure):
            self.call('qa-enable')
        self.assertTrue(self.session.dynamodb.reservation()['retired'])
        self.assertFalse(self.session.dynamodb.state()['enabled'])
        self.success('qa-disable')

    def test_serialized_qa_then_owner_retains_distinct_reservations_and_denies_reactivation(self):
        self.success('qa-create')
        # The unchanged owner group check blocks concurrent authority.
        with self.assertRaises(owner.OwnerOperationError):
            owner._require_group_available(self.session.cognito, pool_id='synthetic',
                                           username='owner-handle', subject='owner-subject', created=True)
        self.success('qa-disable')
        owner._require_group_available(self.session.cognito, pool_id='synthetic',
                                       username='owner-handle', subject='owner-subject', created=True)
        current.provision_single_owner_state(self.session.dynamodb, scope=current.APPROVED_SCOPE,
                                             subject='owner-subject', account_purpose='client-owner')
        snapshot = copy.deepcopy(self.session.dynamodb.items)
        for operation in ('qa-create','qa-enable','qa-reset'):
            with self.assertRaises(mediator.OwnerMediatorFailure):
                self.call(operation)
        self.success('qa-disable')
        for key, value in snapshot.items():
            if key[0] == current.APPROVED_TABLE_NAME:
                self.assertEqual(self.session.dynamodb.items[key], value)

    def test_real_packaged_mediator_and_cli_import_only_packaged_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            builder.build_artifact('ThnAuthAdminV2OwnerOperatorFunction', directory, install_dependencies=False)
            program = (
                "import pathlib,sys; sys.path[:0]=[sys.argv[1],sys.argv[2]]; "
                "import auth_admin_owner_operator_v2 as m, auth_admin_qa_operator_v2 as q, auth_admin_qa_state_v2 as s; "
                "from tools import provision_thn_qa,provision_thn_owner; "
                "assert all(pathlib.Path(x.__file__).is_relative_to(pathlib.Path(sys.argv[1])) for x in (m,q,s,provision_thn_qa,provision_thn_owner)); "
                "import tools; tools.__path__.append(sys.argv[3]); "
                "import test_auth_admin_qa_operator_v2 as t; worker=t.QaOperatorTests(); worker.setUp(); "
                "worker.success('qa-create'); worker.success('qa-enable'); worker.success('qa-reset'); "
                "worker.success('qa-enable'); worker.success('qa-disable'); worker.success('qa-disable'); "
                "assert worker.session.dynamodb.reservation()['retired']; print('packaged QA dispatch passed')"
            )
            result = subprocess.run([sys.executable,'-I','-B','-c',program,directory,str(ROOT/'tests'),str(ROOT/'tools')],
                                    cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('packaged QA dispatch passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
