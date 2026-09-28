#!/usr/bin/env python3
"""Signed TEST-only QA client of the existing owner/QA mediator alias."""
from __future__ import annotations

from collections.abc import Mapping
import getpass
import json
from pathlib import Path
import sys
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tools import provision_thn_owner as owner
from auth_admin_qa_operator_v2 import OPERATIONS, public_result


def build_parser():
    parser = owner.SanitizedArgumentParser(description='Operate the isolated TEST QA account; disable is terminal.')
    operations = parser.add_subparsers(dest='operation', required=True)
    for operation in sorted(OPERATIONS):
        operations.add_parser(operation)
    return parser


def invoke_qa_operator(session: Any, *, operation: str, username: str,
                       temporary_password: str | None = None) -> dict[str, Any]:
    try:
        if getattr(session, 'region_name', None) != owner.APPROVED_AWS_REGION:
            raise owner.OperatorAuthorizationError('QA operator is not authorized')
        identity = session.client('sts').get_caller_identity()
        if not isinstance(identity, Mapping) or not owner._account_is_code_owned(identity.get('Account')):
            raise owner.OperatorAuthorizationError('QA operator is not authorized')
        owner.require_named_operator(str(identity.get('Arn') or ''))
        if not isinstance(operation, str) or operation not in OPERATIONS:
            raise owner.OperatorInputError('QA input is invalid')
        payload = {'contractVersion':1, 'operation':operation, 'username':owner._validate_username(username)}
        if operation in {'qa-create', 'qa-reset'}:
            payload['temporaryPassword'] = owner._validate_temporary_password(temporary_password)
        elif temporary_password is not None:
            raise owner.OperatorInputError('QA input is invalid')
        response = session.client('lambda').get_function_url_config(
            FunctionName=owner.APPROVED_MEDIATOR_FUNCTION, Qualifier=owner.APPROVED_MEDIATOR_QUALIFIER)
        url = response.get('FunctionUrl') if isinstance(response, Mapping) else None
        if not isinstance(url, str) or not owner._FUNCTION_URL_RE.fullmatch(url) or response.get('AuthType') != 'AWS_IAM':
            raise owner.OwnerOperationError('QA operation failed')
        status, headers, raw = owner._signed_function_url_post(
            session, url, json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8'))
        if (status != 200 or not headers.get('content-type','').lower().startswith('application/json')
                or 'no-store' not in headers.get('cache-control','').lower()
                or not isinstance(raw, bytes) or len(raw) > 4096):
            raise owner.OwnerOperationError('QA operation failed')
        return public_result(json.loads(raw.decode('utf-8')), operation)
    except Exception:
        raise owner.OwnerOperationError('QA operation failed') from None


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        username = getpass.getpass('QA account email (not echoed): ').strip()
        password = getpass.getpass('Temporary password: ') if args.operation in {'qa-create', 'qa-reset'} else None
        import boto3
        result = invoke_qa_operator(boto3.Session(region_name=owner.APPROVED_AWS_REGION),
                                   operation=args.operation, username=username, temporary_password=password)
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return 0
    except Exception:
        print('{"ok":false,"error":"QA operation failed"}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
