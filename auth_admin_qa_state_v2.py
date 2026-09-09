"""Read-only QA reservation/epoch contract shared by the two existing v2 roles."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import re
from typing import Any

import auth_admin_current_user_v2 as current

QA_SORT_KEY = 'QA#qa'
RESERVATION_FIELDS = frozenset({'pk', 'sk', 'contractVersion', 'scope', 'subject',
                               'accountPurpose', 'accountHash', 'retired', 'resetPending'})
FENCE_FIELDS = frozenset({'subject', 'accountPurpose', 'accountHash', 'sessionVersion'})


def reject() -> None:
    raise current.CurrentUserStateUnavailable('current user state is unavailable') from None


def read_item(client: Any, sort_key: str) -> dict[str, Any] | None:
    if sort_key not in {QA_SORT_KEY, current.APPROVED_OWNER_BINDING_SORT_KEY}:
        reject()
    try:
        response = client.get_item(
            TableName=current.APPROVED_TABLE_NAME,
            Key=current.marshal_item({'pk': current.APPROVED_PARTITION_KEY, 'sk': sort_key}),
            ConsistentRead=True,
        )
        if not isinstance(response, Mapping) or set(response) - {'Item', 'ResponseMetadata'}:
            reject()
        if 'Item' not in response:
            return None
        item = current.unmarshal_item(response['Item'])
        if not item or item.get('pk') != current.APPROVED_PARTITION_KEY or item.get('sk') != sort_key:
            reject()
        return item
    except Exception:
        reject()


def require_no_owner(client: Any) -> None:
    if read_item(client, current.APPROVED_OWNER_BINDING_SORT_KEY) is not None:
        reject()


def validate_reservation(item: Any) -> dict[str, Any]:
    if (not isinstance(item, Mapping) or set(item) != RESERVATION_FIELDS
            or item.get('pk') != current.APPROVED_PARTITION_KEY or item.get('sk') != QA_SORT_KEY
            or type(item.get('contractVersion')) is not int or item['contractVersion'] != 1
            or item.get('scope') != dict(current.APPROVED_SCOPE)
            or item.get('accountPurpose') != 'qa'
            or not isinstance(item.get('accountHash'), str)
            or re.fullmatch(r'[a-f0-9]{64}', item['accountHash']) is None
            or type(item.get('retired')) is not bool or type(item.get('resetPending')) is not bool):
        reject()
    current._validate_subject(item.get('subject'))
    return deepcopy(dict(item))


def load_reservation(client: Any, *, optional: bool = False) -> dict[str, Any] | None:
    item = read_item(client, QA_SORT_KEY)
    if item is None and optional:
        return None
    return validate_reservation(item)


def validate_fence(value: Any) -> dict[str, Any]:
    if (not isinstance(value, Mapping) or set(value) != FENCE_FIELDS
            or value.get('accountPurpose') != 'qa'
            or not isinstance(value.get('accountHash'), str)
            or re.fullmatch(r'[a-f0-9]{64}', value['accountHash']) is None):
        reject()
    current._validate_subject(value.get('subject'))
    current._validate_session_version(value.get('sessionVersion'))
    return deepcopy(dict(value))


def assert_fence_current(client: Any, value: Any) -> dict[str, Any]:
    fence = validate_fence(value)
    reservation = load_reservation(client)
    if (reservation['retired'] or reservation['resetPending']
            or any(reservation[key] != fence[key] for key in ('subject', 'accountPurpose', 'accountHash'))):
        reject()
    require_no_owner(client)
    current.assert_session_current(client, scope=current.APPROVED_SCOPE, subject=fence['subject'],
                                   account_purpose='qa', session_version=fence['sessionVersion'])
    return fence


def transaction_checks(value: Any, serialize: Any) -> list[dict[str, Any]]:
    """Exact existing ConditionCheckItem permission closes every QA commit race."""
    fence = validate_fence(value)
    checks = []
    for sort_key, expected in (
        ('SUBJECT#' + fence['subject'], {'contractVersion': 1, 'scope': dict(current.APPROVED_SCOPE),
                                      'subject': fence['subject'], 'accountPurpose': 'qa',
                                      'sessionVersion': fence['sessionVersion'], 'enabled': True}),
        (QA_SORT_KEY, {'contractVersion': 1, 'scope': dict(current.APPROVED_SCOPE),
                      'subject': fence['subject'], 'accountPurpose': 'qa',
                      'accountHash': fence['accountHash'], 'retired': False, 'resetPending': False}),
    ):
        checks.append({'ConditionCheck': {
            'TableName': current.APPROVED_TABLE_NAME,
            'Key': serialize({'pk': current.APPROVED_PARTITION_KEY, 'sk': sort_key}),
            'ConditionExpression': ' AND '.join('#' + key + ' = :' + key for key in expected),
            'ExpressionAttributeNames': {'#' + key: key for key in expected},
            'ExpressionAttributeValues': serialize({':' + key: val for key, val in expected.items()}),
            'ReturnValuesOnConditionCheckFailure': 'NONE',
        }})
    checks.append({'ConditionCheck': {
        'TableName': current.APPROVED_TABLE_NAME,
        'Key': serialize({'pk': current.APPROVED_PARTITION_KEY, 'sk': current.APPROVED_OWNER_BINDING_SORT_KEY}),
        'ConditionExpression': 'attribute_not_exists(#pk) AND attribute_not_exists(#sk)',
        'ExpressionAttributeNames': {'#pk': 'pk', '#sk': 'sk'},
        'ReturnValuesOnConditionCheckFailure': 'NONE',
    }})
    return checks
