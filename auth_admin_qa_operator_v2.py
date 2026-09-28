"""Server-fixed QA lifecycle inside the existing serialized TEST IAM mediator.

No handler, AWS resource, browser entrypoint or caller-selected purpose/scope.
The owner CLI and its singleton are deliberately not extended or repurposed.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import time
import uuid
from typing import Any

import auth_admin_current_user_v2 as current
import auth_admin_qa_state_v2 as qa_state
from tools import provision_thn_owner as owner

OPERATIONS = frozenset({'qa-create', 'qa-enable', 'qa-reset', 'qa-disable'})


def public_result(value: Any, operation: str) -> dict[str, Any]:
    fields = {'ok', 'operation', 'accountPurpose', 'sessionVersion', 'enabled'}
    if (not isinstance(value, Mapping) or set(value) != fields or operation not in OPERATIONS
            or value.get('ok') is not True or value.get('operation') != operation
            or value.get('accountPurpose') != 'qa'
            or type(value.get('sessionVersion')) is not int or value['sessionVersion'] < 1
            or type(value.get('enabled')) is not bool
            or value['enabled'] is not (operation == 'qa-enable')):
        qa_state.reject()
    return dict(value)


def _result(state: Mapping[str, Any], operation: str) -> dict[str, Any]:
    return public_result({'ok': True, 'operation': operation, 'accountPurpose': state['accountPurpose'],
                          'sessionVersion': state['sessionVersion'], 'enabled': state['enabled']}, operation)


def audit(client: Any, *, operation: str, phase: str, operation_id: str, result: Any = None) -> None:
    if operation not in OPERATIONS or phase not in {'intent', 'completed', 'failed'}:
        qa_state.reject()
    now = int(time.time() * 1000)
    item = {'pk': owner.APPROVED_AUDIT_PARTITION_KEY, 'sk': f'EVENT#{now:013d}#{uuid.uuid4().hex}',
            'contractVersion': 1, 'operation': operation, 'phase': phase, 'operationId': operation_id,
            'accountPurpose': 'qa', 'occurredAtEpochMs': now}
    if phase == 'completed':
        safe = public_result(result, operation)
        item.update(sessionVersion=safe['sessionVersion'], enabled=safe['enabled'])
    elif result is not None:
        qa_state.reject()
    client.put_item(TableName=owner.APPROVED_AUDIT_TABLE_NAME, Item=current.marshal_item(item),
                    ConditionExpression='attribute_not_exists(#pk) AND attribute_not_exists(#sk)',
                    ExpressionAttributeNames={'#pk':'pk', '#sk':'sk'}, ReturnValues='NONE',
                    ReturnValuesOnConditionCheckFailure='NONE')


class QaState:
    def __init__(self, client: Any):
        self.client = client

    def load(self, subject: str, account_hash: str) -> tuple[dict[str, Any], dict[str, Any]]:
        reservation = qa_state.load_reservation(self.client)
        if reservation['subject'] != subject or reservation['accountHash'] != account_hash:
            qa_state.reject()
        state = current.load_current_user_state(self.client, scope=current.APPROVED_SCOPE, subject=subject)
        if state['accountPurpose'] != 'qa' or (reservation['retired'] and state['enabled']):
            qa_state.reject()
        return reservation, state

    def create(self, subject: str, account_hash: str) -> dict[str, Any]:
        reservation = {'pk': current.APPROVED_PARTITION_KEY, 'sk': qa_state.QA_SORT_KEY,
                       'contractVersion': 1, 'scope': dict(current.APPROVED_SCOPE), 'subject': subject,
                       'accountPurpose': 'qa', 'accountHash': account_hash, 'retired': False, 'resetPending': False}
        qa_state.validate_reservation(reservation)
        state = {'contractVersion': 1, 'scope': dict(current.APPROVED_SCOPE), 'subject': subject,
                 'accountPurpose': 'qa', 'sessionVersion': 1, 'enabled': False}
        items = [reservation, current._storage_item(state)]
        try:
            self.client.transact_write_items(TransactItems=[{'Put': {
                'TableName': current.APPROVED_TABLE_NAME, 'Item': current.marshal_item(item),
                'ConditionExpression':'attribute_not_exists(#pk) AND attribute_not_exists(#sk)',
                'ExpressionAttributeNames':{'#pk':'pk','#sk':'sk'}, 'ReturnValuesOnConditionCheckFailure':'NONE',
            }} for item in items], ReturnConsumedCapacity='NONE', ReturnItemCollectionMetrics='NONE')
        except Exception:
            if self.load(subject, account_hash) != (reservation, state):
                qa_state.reject()
        return state

    def transition(self, reservation: dict[str, Any], state: dict[str, Any], *,
                   enabled: bool, retired: bool, reset_pending: bool, bump: bool = True) -> dict[str, Any]:
        next_reservation = {**reservation, 'retired': retired, 'resetPending': reset_pending}
        next_state = {**state, 'enabled': enabled, 'sessionVersion': state['sessionVersion'] + int(bump)}
        writes = []
        for previous, following in ((reservation, next_reservation),
                                    (current._storage_item(state), current._storage_item(next_state))):
            expected = {key: value for key, value in previous.items() if key not in {'pk','sk'}}
            changes = {key: value for key, value in following.items() if key not in {'pk','sk'} and previous[key] != value}
            if not changes:
                # Keep the reservation checked by the same transaction without new IAM.
                changes = {'accountPurpose': 'qa'}
            writes.append({'Update': {
                'TableName': current.APPROVED_TABLE_NAME,
                'Key': current.marshal_item({'pk':previous['pk'], 'sk':previous['sk']}),
                'ConditionExpression':' AND '.join('#' + key + ' = :old_' + key for key in expected),
                'UpdateExpression':'SET ' + ', '.join('#' + key + ' = :new_' + key for key in changes),
                'ExpressionAttributeNames':{'#' + key:key for key in expected},
                'ExpressionAttributeValues':current.marshal_item({**{':old_' + key:value for key,value in expected.items()},
                                                                **{':new_' + key:value for key,value in changes.items()}}),
                'ReturnValuesOnConditionCheckFailure':'NONE',
            }})
        try:
            self.client.transact_write_items(TransactItems=writes, ReturnConsumedCapacity='NONE', ReturnItemCollectionMetrics='NONE')
        except Exception:
            if self.load(state['subject'], reservation['accountHash']) != (next_reservation, next_state):
                qa_state.reject()
        return next_state


def _remove_qa_authority(cognito: Any, pool_id: str, username: str) -> None:
    """Attempt every revocation leg; a partial provider outcome is never success."""
    failed = False
    for method, extra in ((cognito.admin_disable_user, {}), (cognito.admin_user_global_sign_out, {}),
                          (cognito.admin_remove_user_from_group, {'GroupName':owner.APPROVED_GROUP_NAME})):
        try:
            method(UserPoolId=pool_id, Username=username, **extra)
        except Exception:
            failed = True
    if failed:
        qa_state.reject()
    user = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    groups = owner._pages(cognito.admin_list_groups_for_user, 'Groups', UserPoolId=pool_id, Username=username, Limit=60)
    if user.get('Enabled') is not False or any(group.get('GroupName') == owner.APPROVED_GROUP_NAME for group in groups):
        qa_state.reject()


def execute_operation(session: Any, *, dynamodb: Any, operation: str, username: str,
                      temporary_password: str | None = None) -> dict[str, Any]:
    """Called only after the existing IAM URL validator; no direct CLI writes."""
    if getattr(session, 'region_name', None) != owner.APPROVED_AWS_REGION or operation not in OPERATIONS:
        qa_state.reject()
    username = owner._validate_username(username)
    if operation in {'qa-create', 'qa-reset'}:
        temporary_password = owner._validate_temporary_password(temporary_password)
    elif temporary_password is not None:
        qa_state.reject()
    account_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()
    state_store = QaState(dynamodb)
    operation_id = uuid.uuid4().hex
    audit(dynamodb, operation=operation, phase='intent', operation_id=operation_id)
    try:
        # Reserved concurrency=1 and the existing sole IAM mediator writer serialize
        # this strong preflight with all unchanged owner operations.
        if operation != 'qa-disable':
            qa_state.require_no_owner(dynamodb)
        prior = qa_state.load_reservation(dynamodb, optional=True)
        if prior is not None and (prior['accountHash'] != account_hash or (prior['retired'] and operation != 'qa-disable')):
            qa_state.reject()
        if prior is None and operation != 'qa-create':
            qa_state.reject()
        if operation in {'qa-disable', 'qa-reset'}:
            # The exact subject comes only from the validated server reservation.
            # Revoke our authority before any provider/discovery dependency can fail.
            reservation, state = state_store.load(prior['subject'], account_hash)
            if operation == 'qa-reset' or not reservation['retired']:
                state_store.transition(reservation, state, enabled=False,
                    retired=operation == 'qa-disable', reset_pending=operation == 'qa-reset')
        cognito = session.client('cognito-idp')
        resources = owner.discover_dedicated_resources(cognito, session.client('cloudformation'))
        pool_id = resources['userPoolId']
        created = False
        try:
            user = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
        except Exception as error:
            if operation != 'qa-create' or prior is not None or owner._provider_error_code(error) != 'UserNotFoundException':
                raise
            try:
                user = cognito.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword=temporary_password,
                    MessageAction='SUPPRESS', UserAttributes=[{'Name':'email','Value':username}, {'Name':'email_verified','Value':'true'}])
                created = True
            except Exception:
                # Do not proceed after ambiguous provider creation. No QA state exists;
                # a later invocation may reconcile the exact pre-existing identity.
                try:
                    observed = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
                    handle, _ = owner._user_identity(observed, created=False, expected_email=username)
                    cognito.admin_disable_user(UserPoolId=pool_id, Username=handle)
                except Exception:
                    pass
                raise
        handle, subject = owner._user_identity(user, created=created, expected_email=username)
        if operation == 'qa-create':
            in_group = owner._require_group_available(cognito, pool_id=pool_id, username=handle, subject=subject, created=created)
            state = state_store.create(subject, account_hash)
            try:
                cognito.admin_disable_user(UserPoolId=pool_id, Username=handle)
                if not in_group:
                    cognito.admin_add_user_to_group(UserPoolId=pool_id, Username=handle, GroupName=owner.APPROVED_GROUP_NAME)
                owner._require_exact_user_group(cognito, pool_id=pool_id, username=handle, subject=subject)
                if cognito.admin_get_user(UserPoolId=pool_id, Username=handle).get('Enabled') is not False:
                    qa_state.reject()
            except Exception:
                try:
                    _remove_qa_authority(cognito, pool_id, handle)
                except Exception:
                    pass
                raise
        else:
            reservation, state = state_store.load(subject, account_hash)
            if operation == 'qa-disable':
                _remove_qa_authority(cognito, pool_id, handle)
            elif operation == 'qa-reset':
                # Remain pending/disabled after any partial or ambiguous reset.
                cognito.admin_disable_user(UserPoolId=pool_id, Username=handle)
                cognito.admin_user_global_sign_out(UserPoolId=pool_id, Username=handle)
                cognito.admin_set_user_password(UserPoolId=pool_id, Username=handle, Password=temporary_password, Permanent=False)
                try:
                    cognito.admin_delete_software_token(UserPoolId=pool_id, Username=handle)
                except Exception as error:
                    if owner._provider_error_code(error) != 'ResourceNotFoundException':
                        raise
                reservation, state = state_store.load(subject, account_hash)
                state = state_store.transition(reservation, state, enabled=False, retired=False, reset_pending=False, bump=False)
            else:
                if reservation['resetPending']:
                    qa_state.reject()
                owner._require_exact_user_group(cognito, pool_id=pool_id, username=handle, subject=subject)
                try:
                    cognito.admin_enable_user(UserPoolId=pool_id, Username=handle)
                    if not state['enabled']:
                        state = state_store.transition(reservation, state, enabled=True, retired=False, reset_pending=False)
                except Exception:
                    # Never leave an uncertain enable usable. Retire state first;
                    # retry qa-disable can finish any provider cleanup failure.
                    try:
                        reservation, state = state_store.load(subject, account_hash)
                        state_store.transition(reservation, state, enabled=False, retired=True, reset_pending=False)
                    finally:
                        _remove_qa_authority(cognito, pool_id, handle)
                    raise
        result = _result(state, operation)
    except Exception:
        try:
            audit(dynamodb, operation=operation, phase='failed', operation_id=operation_id)
        except Exception:
            pass
        raise owner.OwnerOperationError('QA operation failed') from None
    try:
        audit(dynamodb, operation=operation, phase='completed', operation_id=operation_id, result=result)
    except Exception:
        if operation == 'qa-enable':
            try:
                reservation, state = state_store.load(subject, account_hash)
                state_store.transition(reservation, state, enabled=False, retired=True, reset_pending=False)
            finally:
                _remove_qa_authority(cognito, pool_id, handle)
        raise owner.OwnerOperationError('QA operation failed') from None
    return result
