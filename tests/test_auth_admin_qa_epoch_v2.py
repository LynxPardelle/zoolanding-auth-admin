"""QA ephemeral epochs cannot survive reset, re-enable, retirement or aliasing."""
import copy
import importlib.util
import unittest
from unittest.mock import patch

import auth_admin_session_v2 as auth
import test_auth_admin_qa_operator_v2 as operator_tests
from test_auth_admin_qa_operator_v2 import QA_EMAIL, QA_SUBJECT, QA_USERNAME
from test_auth_admin_session_v2 import FakeV2Store, FakeCognito, NOW, hash_text, signin_event, v2_event
from test_auth_admin_session_v2 import cookie_value, response_cookies
from test_auth_admin_session_v2 import AwsProviderError
from test_auth_admin_session_v2_store import InspectableDynamoAuthV2Store, decoded_item
from test_auth_admin_v2_transaction_errors import TransactionCanceledException
import auth_admin_qa_state_v2 as qa_state


class EpochTransactionClient:
    """Evaluate the real emitted current-state ConditionChecks at commit time."""
    def __init__(self, db, before=None):
        self.db = db
        self.before = before
        self.calls = []
        self.committed = []

    def transact_write_items(self, **request):
        self.calls.append(copy.deepcopy(request))
        if self.before:
            action, self.before = self.before, None
            action()
        writes = request['TransactItems']
        checks = [item['ConditionCheck'] for item in writes if 'ConditionCheck' in item]
        if len(checks) != 3:
            raise AssertionError('missing QA state/reservation/owner-absence transaction fence')
        for index, operation in enumerate(writes):
            if 'ConditionCheck' not in operation:
                continue
            check = operation['ConditionCheck']
            key = decoded_item(check['Key'])
            actual = self.db.items.get((check['TableName'], key['pk'], key['sk']))
            names = check['ExpressionAttributeNames']
            values = decoded_item(check.get('ExpressionAttributeValues', {}))
            valid = True
            for expression in check['ConditionExpression'].split(' AND '):
                if expression.startswith('attribute_not_exists('):
                    valid = valid and actual is None
                else:
                    field, value = expression.split(' = ')
                    valid = valid and actual is not None and actual.get(names[field]) == values[value]
            if not valid:
                codes = ['None'] * len(writes)
                codes[index] = 'ConditionalCheckFailed'
                raise TransactionCanceledException(codes)
        self.committed.append(copy.deepcopy(writes))


class QaEpochTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('auth_admin_qa_state_v2'), 'QA epoch persistence is missing')
        self.operator = operator_tests.QaOperatorTests()
        self.operator.setUp()
        self.operator.success('qa-create')
        self.operator.success('qa-enable')
        self.db = self.operator.session.dynamodb
        self.store = FakeV2Store()
        self.store.current_users[QA_SUBJECT] = {key: value for key, value in self.db.state().items() if key not in {'pk', 'sk'}}
        self.cognito = FakeCognito(current_user_subject=QA_SUBJECT, current_username=QA_USERNAME)
        self.patchers = [patch.object(auth, '_current_user_client', return_value=self.db),
                         patch.object(auth, '_session_store', return_value=self.store),
                         patch.object(auth, '_cognito_client', return_value=self.cognito),
                         patch.object(auth, '_cognito_configuration', return_value=('us-east-1','us-east-1_THNTEST','thnv2client')),
                         patch.object(auth, '_now_epoch', return_value=NOW)]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def challenge(self, **override):
        fields = {'challengeName': 'MFA_SETUP', 'cognitoSession': 'synthetic-provider-session',
                  'username': QA_USERNAME, 'accountHash': hash_text(QA_EMAIL), **override}
        auth._new_challenge_response(fields, store=self.store)
        return copy.deepcopy(next(reversed(self.store.ephemeral.values())))

    def test_new_qa_challenge_has_server_owned_reservation_subject_version_fence(self):
        record = self.challenge()
        self.assertIn('qaFence', record)
        self.assertEqual(record['qaFence'], {'subject': QA_SUBJECT, 'accountPurpose':'qa',
                                           'sessionVersion':2, 'accountHash':hash_text(QA_EMAIL)})
        self.assertTrue(auth._valid_ephemeral_record(record, expected_type='authChallengeV2', now=NOW))
        record['qaFence']['sessionVersion'] = 99
        self.assertFalse(auth._valid_ephemeral_record(record, expected_type='authChallengeV2', now=NOW))

    def test_reset_then_reenable_rejects_old_challenge_before_provider_continuation(self):
        record = self.challenge()
        self.operator.success('qa-reset')
        self.operator.success('qa-enable')
        self.assertTrue(callable(getattr(auth, '_require_qa_epoch', None)), 'QA continuation guard is missing')
        with self.assertRaises(auth.AuthV2AuthFailed):
            auth._require_qa_epoch(record)

    def test_provider_preflight_failure_already_revokes_existing_qa_cookie_and_challenge(self):
        from test_auth_admin_v2_atomic_store_contract import session_record
        for operation in ('qa-disable', 'qa-reset'):
            for failure in ('discovery', 'identity'):
                with self.subTest(operation=operation, failure=failure):
                    self.operator.setUp()
                    self.operator.success('qa-create')
                    self.operator.success('qa-enable')
                    self.db = self.operator.session.dynamodb
                    with patch.object(auth, '_current_user_client', return_value=self.db), patch.object(
                        auth, '_require_active_service_binding', return_value={}
                    ):
                        challenge = self.challenge()
                        session = {**session_record(session_id_hash=hash_text('synthetic-qa-cookie')),
                                   'subject': QA_SUBJECT, 'accountPurpose': 'qa', 'sessionVersion': 2,
                                   'accountHash': hash_text(QA_EMAIL), 'qaFence': challenge['qaFence']}
                        self.store.sessions[session['sessionIdHash']] = session
                        event = v2_event('GET', '/auth-v2/session/me',
                                         cookies=[auth.SESSION_COOKIE_NAME + '=synthetic-qa-cookie'])
                        self.assertEqual(auth.lambda_handler(event, None)['statusCode'], 200)
                        target = (patch.object(operator_tests.owner, 'discover_dedicated_resources', side_effect=RuntimeError('synthetic discovery failure'))
                            if failure == 'discovery' else patch.object(self.operator.session.cognito, 'admin_get_user', side_effect=RuntimeError('synthetic identity failure')))
                        with target, self.assertRaises(operator_tests.mediator.OwnerMediatorFailure):
                            self.operator.call(operation)
                        self.assertEqual(auth.lambda_handler(event, None)['statusCode'], 401)
                        with self.assertRaises(auth.AuthV2AuthFailed):
                            auth._require_qa_epoch(challenge)

    def test_alias_cannot_fall_back_to_unfenced_owner_challenge(self):
        with self.assertRaises(auth.AuthV2AuthFailed):
            self.challenge(accountHash=hash_text('alias@example.test'))
        self.assertEqual(self.store.ephemeral, {})

    def test_qa_finalization_without_a_fence_is_denied(self):
        claims = {'sub': QA_SUBJECT, 'token_use':'id', 'cognito:groups':['journal-owner']}
        with patch.object(auth, '_verify_id_token', return_value=claims):
            with self.assertRaises(auth.AuthV2AuthFailed):
                auth._new_session_response({'IdToken':'synthetic'}, account_hash=hash_text(QA_EMAIL), store=self.store)
        self.assertEqual(self.store.sessions, {})

    def test_retired_qa_cannot_begin_a_new_challenge_even_with_provider_success(self):
        self.operator.success('qa-disable')
        with self.assertRaises(auth.AuthV2AuthFailed):
            self.challenge()
        self.assertEqual(self.store.ephemeral, {})

    def test_retained_retired_qa_reservation_does_not_relabel_owner_challenges(self):
        self.operator.success('qa-disable')
        self.cognito.current_user_subject = 'owner-subject-synthetic'
        self.cognito.current_username = 'owner@example.test'
        fields = {'challengeName': 'SOFTWARE_TOKEN_MFA', 'cognitoSession': 'synthetic-owner-provider',
                  'username': 'owner@example.test', 'accountHash': hash_text('owner@example.test')}
        response = auth._new_challenge_response(fields, store=self.store)
        self.assertEqual(response['statusCode'], 200)
        record = next(reversed(self.store.ephemeral.values()))
        self.assertNotIn('qaFence', record)
        self.assertIsNone(auth._require_qa_epoch(record))

    def test_qa_lookup_missing_account_and_wrong_password_are_enumeration_safe_and_counted(self):
        for lifecycle in ('active', 'retired-with-owner'):
            with self.subTest(lifecycle=lifecycle):
                if lifecycle == 'retired-with-owner':
                    self.operator.success('qa-disable')
                    operator_tests.current.provision_single_owner_state(self.db,
                        scope=operator_tests.current.APPROVED_SCOPE, subject='owner-subject-synthetic', account_purpose='client-owner')
                known_email = QA_EMAIL if lifecycle == 'active' else 'owner@example.test'
                known_subject = QA_SUBJECT if lifecycle == 'active' else 'owner-subject-synthetic'
                responses = []
                for missing in (True, False):
                    store = FakeV2Store()
                    cognito = FakeCognito(current_user_subject=known_subject,
                        current_username=known_email,
                        current_user_error=AwsProviderError('UserNotFoundException') if missing else None,
                        auth_error=AwsProviderError('NotAuthorizedException'))
                    email = 'missing@example.test' if missing else known_email
                    with patch.object(auth, '_session_store', return_value=store), patch.object(
                        auth, '_cognito_client', return_value=cognito
                    ), patch.object(auth, '_require_active_service_binding', return_value={}):
                        response = auth.lambda_handler(signin_event(email), None)
                    responses.append(response)
                    self.assertEqual(response['statusCode'], 401)
                    self.assertEqual(store.failure_events[('signin', 'account', hash_text(email))], [NOW])
                    self.assertEqual(store.failure_events[('signin', 'ip', hash_text('203.0.113.10'))], [NOW])
                self.assertEqual(responses[0], responses[1])

    def test_qa_provider_lookup_outage_remains_unavailable_and_releases_attempt(self):
        self.cognito.current_user_error = AwsProviderError('ServiceUnavailableException')
        with patch.object(auth, '_require_active_service_binding', return_value={}):
            response = auth.lambda_handler(signin_event(QA_EMAIL), None)
        self.assertEqual(response['statusCode'], 503)
        self.assertTrue(all(not events for events in self.store.failure_events.values()))

    def test_signin_paused_at_provider_cannot_capture_post_reset_reenabled_epoch(self):
        def provider(**request):
            self.operator.success('qa-reset')
            self.operator.success('qa-enable')
            return {'ChallengeName':'MFA_SETUP', 'Session':'synthetic-paused-provider',
                    'ChallengeParameters':{'USERNAME':QA_USERNAME}}
        with patch.object(self.cognito, 'admin_initiate_auth', side_effect=provider), patch.object(
            auth, '_require_active_service_binding', return_value={}
        ):
            response = auth.lambda_handler(signin_event(QA_EMAIL), None)
        self.assertEqual(response['statusCode'], 401)
        self.assertEqual(self.store.ephemeral, {})

    def test_initial_challenge_commit_is_transactionally_denied_after_reset_and_reenable(self):
        record = self.challenge()
        def race():
            self.operator.success('qa-reset')
            self.operator.success('qa-enable')
        client = EpochTransactionClient(self.db, race)
        with self.assertRaises(auth.AuthV2Unavailable):
            InspectableDynamoAuthV2Store(client).put_ephemeral(record)
        self.assertEqual(client.committed, [])
        self.assertEqual(len(client.calls[0]['TransactItems']), 4)

    def test_continuation_and_session_commit_deny_each_current_reservation_or_owner_race(self):
        for next_type in ('authMfaEnrollmentV2','authSessionV2'):
            for drift in ('reset', 'retired', 'owner', 'subject', 'purpose'):
                with self.subTest(next_type=next_type, drift=drift):
                    self.operator.setUp()
                    self.operator.success('qa-create')
                    self.operator.success('qa-enable')
                    self.db = self.operator.session.dynamodb
                    with patch.object(auth, '_current_user_client', return_value=self.db):
                        record = self.challenge()
                    fence = record['qaFence']
                    if next_type == 'authMfaEnrollmentV2':
                        next_item = {**record,'recordType':next_type,'stateIdHash':'d'*64}
                        next_item.pop('challengeName')
                        next_item['stateBindingHash'] = auth._ephemeral_state_binding_hash(next_item)
                    else:
                        from test_auth_admin_v2_atomic_store_contract import session_record
                        next_item = {**session_record(), 'subject':QA_SUBJECT, 'accountPurpose':'qa',
                                     'accountHash':hash_text(QA_EMAIL), 'sessionVersion':2, 'qaFence':fence}
                    def race():
                        if drift == 'reset':
                            self.operator.success('qa-reset')
                            self.operator.success('qa-enable')
                        elif drift == 'retired':
                            self.operator.success('qa-disable')
                        elif drift == 'owner':
                            import auth_admin_current_user_v2 as current
                            key = (current.APPROVED_TABLE_NAME,current.APPROVED_PARTITION_KEY,current.APPROVED_OWNER_BINDING_SORT_KEY)
                            self.db.items[key] = {'pk':key[1],'sk':key[2]}
                        else:
                            self.db.reservation()[{'subject':'subject','purpose':'accountPurpose'}[drift]] = 'drift'
                    client = EpochTransactionClient(self.db, race)
                    actual = InspectableDynamoAuthV2Store(client).transition_ephemeral_claim('a'*64,
                        expected_type='authChallengeV2', expected_binding_hash=record['stateBindingHash'],
                        expected_account_hash=hash_text(QA_EMAIL), claim_token='synthetic-claim', now=NOW, next_item=next_item)
                    self.assertFalse(actual)
                    self.assertEqual(client.committed, [])

    def test_reset_during_mfa_setup_returns_no_setup_secret_or_successor(self):
        record = self.challenge()
        # Use known opaque cookie values with the real hash/claim path.
        record['stateIdHash'] = hash_text('synthetic-cookie')
        record['csrfHash'] = hash_text('synthetic-csrf')
        record['stateBindingHash'] = auth._ephemeral_state_binding_hash(record)
        self.store.ephemeral = {record['stateIdHash']: record}
        def associate(**request):
            self.operator.success('qa-reset')
            self.operator.success('qa-enable')
            return {'SecretCode':'SYNTHETIC-NOT-A-SECRET','Session':'synthetic-associated'}
        event = v2_event('POST','/auth-v2/session/mfa/setup',{},
            cookies=[auth.CHALLENGE_COOKIE_NAME+'=synthetic-cookie',auth.CHALLENGE_CSRF_COOKIE_NAME+'=synthetic-csrf'],
            headers={'x-zlp-csrf':'synthetic-csrf'})
        with patch.object(self.cognito,'associate_software_token',side_effect=associate):
            with self.assertRaises(auth.AuthV2AuthFailed):
                auth._mfa_setup_response(event)
        self.assertEqual(len(self.store.ephemeral), 1)

    def test_qa_mfa_enrollment_session_and_post_retirement_denial_use_real_handlers(self):
        with patch.object(auth,'_require_active_service_binding',return_value={}):
            self.cognito.auth_response = {'ChallengeName':'MFA_SETUP','Session':'synthetic-provider',
                                         'ChallengeParameters':{'USERNAME':QA_USERNAME}}
            start = auth.lambda_handler(signin_event(QA_EMAIL), None)
            cookies = response_cookies(start)
            state_cookie = cookie_value(cookies, auth.CHALLENGE_COOKIE_NAME)
            csrf = cookie_value(cookies, auth.CHALLENGE_CSRF_COOKIE_NAME)
            setup = auth.lambda_handler(v2_event('POST','/auth-v2/session/mfa/setup',{},
                cookies=[auth.CHALLENGE_COOKIE_NAME+'='+state_cookie,auth.CHALLENGE_CSRF_COOKIE_NAME+'='+csrf],
                headers={'x-zlp-csrf':csrf}), None)
            self.assertEqual(setup['statusCode'], 200)
            cookies = response_cookies(setup)
            enroll = cookie_value(cookies, auth.MFA_ENROLLMENT_COOKIE_NAME)
            csrf = cookie_value(cookies, auth.MFA_ENROLLMENT_CSRF_COOKIE_NAME)
            event = v2_event('POST','/auth-v2/session/mfa/verify',{'code':'123456'},
                cookies=[auth.MFA_ENROLLMENT_COOKIE_NAME+'='+enroll,auth.MFA_ENROLLMENT_CSRF_COOKIE_NAME+'='+csrf],
                headers={'x-zlp-csrf':csrf})
            with patch.object(auth,'_verify_id_token', return_value={'sub':QA_SUBJECT,'token_use':'id','cognito:groups':['journal-owner']}):
                success = auth.lambda_handler(event, None)
            self.assertEqual(success['statusCode'], 200)
            self.assertNotIn('qaFence', success['body'])
            self.operator.success('qa-disable')
            replay = auth.lambda_handler(event, None)
            self.assertEqual(replay['statusCode'], 401)


if __name__ == '__main__':
    unittest.main()
