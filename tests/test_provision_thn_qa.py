"""The QA operator remains a thin signed client, never a direct data writer."""
import importlib
import importlib.util
import io
from contextlib import redirect_stderr
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from test_provision_thn_owner import RecordingSession, TEMPORARY_PASSWORD
from tools import provision_thn_owner as owner


class QaCliTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('tools.provision_thn_qa'), 'signed QA CLI is missing')
        self.cli = importlib.import_module('tools.provision_thn_qa')

    def test_cli_sends_only_closed_qa_operation_to_existing_signed_url(self):
        session = RecordingSession()
        result = {'ok':True, 'operation':'qa-create', 'accountPurpose':'qa', 'sessionVersion':1, 'enabled':False}
        with patch.object(owner, '_signed_function_url_post', return_value=(200,
            {'content-type':'application/json', 'cache-control':'no-store'}, json.dumps(result).encode())) as post:
            actual = self.cli.invoke_qa_operator(session, operation='qa-create', username='qa@example.test', temporary_password=TEMPORARY_PASSWORD)
        self.assertEqual(actual, result)
        self.assertEqual(session.client_names, ['sts', 'lambda'])
        self.assertEqual(json.loads(post.call_args.args[2]), {'contractVersion':1,'operation':'qa-create',
                          'username':'qa@example.test','temporaryPassword':TEMPORARY_PASSWORD})
        self.assertEqual(session.lambda_client.calls, [{'FunctionName':owner.APPROVED_MEDIATOR_FUNCTION,
                                                       'Qualifier':owner.APPROVED_MEDIATOR_QUALIFIER}])

    def test_cli_rejects_owner_reply_and_cannot_choose_purpose_scope_or_direct_invoke(self):
        session = RecordingSession()
        result = {'ok':True, 'operation':'qa-enable', 'accountPurpose':'client-owner', 'sessionVersion':2, 'enabled':True}
        with patch.object(owner, '_signed_function_url_post', return_value=(200,
            {'content-type':'application/json', 'cache-control':'no-store'}, json.dumps(result).encode())):
            with self.assertRaises(Exception):
                self.cli.invoke_qa_operator(session, operation='qa-enable', username='qa@example.test')
        for arguments in (['create'], ['qa-enable','--accountPurpose','qa'], ['qa-reset','--region','other']):
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                self.cli.build_parser().parse_args(arguments)

    def test_qa_client_is_available_from_the_exact_owner_artifact_only(self):
        from tools.build_lambda_artifact import SOURCE_ALLOWLIST
        self.assertIn('tools/provision_thn_qa.py', SOURCE_ALLOWLIST['ThnAuthAdminV2OwnerOperatorFunction'])
        self.assertTrue(all('tools/provision_thn_qa.py' not in files for target,files in SOURCE_ALLOWLIST.items()
                            if target != 'ThnAuthAdminV2OwnerOperatorFunction'))


if __name__ == '__main__':
    unittest.main()
