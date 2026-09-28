import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
class ClosedEnvironmentProfileTests(unittest.TestCase):
    def run_profile(self, environment, expression):
        env = dict(os.environ)
        if environment is None:
            env.pop("THN_DEPLOYMENT_ENVIRONMENT", None)
        else:
            env["THN_DEPLOYMENT_ENVIRONMENT"] = environment
        return subprocess.run([sys.executable, "-c", expression], cwd=ROOT, env=env, text=True, capture_output=True)

    def test_test_contract_is_unchanged(self):
        result = self.run_profile(None, "import thn_environment_profile as p; print(p.PROFILE['environment'], p.PROFILE['cookieNamespace'], p.PROFILE['adminHost'])")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "test endefiz7dkk635k6di6k admin-test.thehairnarrative.com")

    def test_production_has_distinct_closed_coordinates(self):
        result = self.run_profile("production", "import thn_environment_profile as p; print(p.PROFILE['environment'], p.PROFILE['samEnvironment'], p.PROFILE['cookieNamespace'], p.PROFILE['registryPartitionKey'], p.PROFILE['authStack'])")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "production prod ltnafwb6videyraictgp SERVICE_BINDING#production#thn-journal-production-v2 zoolanding-auth-admin-prod")

    def test_aliases_and_unknown_environment_fail_closed(self):
        for environment in ("prod", "dev", "Production", "", " production", "test "):
            with self.subTest(environment=environment):
                self.assertNotEqual(self.run_profile(environment, "import thn_environment_profile").returncode, 0)

    def test_profile_is_immutable(self):
        self.assertNotEqual(self.run_profile("production", "from thn_environment_profile import PROFILE; PROFILE['environment']='test'").returncode, 0)

    def test_runtime_coordinates_are_sealed_at_import(self):
        code = "import os; from thn_environment_profile import PROFILE; os.environ['THN_DEPLOYMENT_ENVIRONMENT']='test'; assert PROFILE['environment']=='production'"
        result = self.run_profile("production", code)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_session_scope_tables_and_cookie_reject_test_coordinates(self):
        code = "import auth_admin_session_v2 as s, auth_admin_current_user_v2 as u; assert s.ENVIRONMENT=='production'; assert s.SESSION_TABLE_NAME=='zoolanding-auth-admin-prod-ThnSessionV2'; assert s.COOKIE_NAMESPACE=='ltnafwb6videyraictgp'; assert u.APPROVED_PARTITION_KEY=='CURRENT_USER#production#thn-journal-production-v2'; assert u._ACCOUNT_PURPOSES==frozenset({'client-owner'})"
        result = self.run_profile("production", code)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_production_registry_refuses_test_record(self):
        code = "from tests.test_service_binding_registry_consumer_v2 import active_record, EXPECTED_DESCRIPTOR, TRUSTED_RESOURCE_SCOPE; import service_binding_registry_consumer_v2 as c; c._validate_record(active_record(), expected_descriptor=EXPECTED_DESCRIPTOR, trusted_resource_scope=TRUSTED_RESOURCE_SCOPE)"
        result = self.run_profile("production", code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RegistryConsumerError", result.stderr)

    def test_production_registry_accepts_matching_closed_record(self):
        code = "from tests.test_service_binding_registry_consumer_v2 import active_record, EXPECTED_DESCRIPTOR, TRUSTED_RESOURCE_SCOPE; import service_binding_registry_consumer_v2 as c; r=active_record(); r.update(c._FIXED_RECORD_FIELDS); r['reservationOwner']=dict(c._RESERVATION_OWNER); r['resourceBindings']=c._expected_resource_bindings(TRUSTED_RESOURCE_SCOPE); c._validate_record(r, expected_descriptor=EXPECTED_DESCRIPTOR, trusted_resource_scope=TRUSTED_RESOURCE_SCOPE)"
        result = self.run_profile("production", code)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_production_authorizer_accepts_only_production_origin_and_stage(self):
        code = "import os; from tests.test_auth_admin_origin_authorizer_v2 import _event,_digest,CURRENT_SECRET; import auth_admin_origin_authorizer_v2 as a; e=_event(); e['requestContext']['stage']='prod'; e['routeArn']=e['routeArn'].replace('/test/','/prod/'); e['headers']['x-forwarded-host']='admin.thehairnarrative.com'; e['headers']['origin']='https://admin.thehairnarrative.com'; os.environ['THN_AUTH_V2_ORIGIN_HEADER_SHA256_CURRENT']=_digest(CURRENT_SECRET); assert a.lambda_handler(e,None)['isAuthorized'] is True; e['headers']['origin']='https://admin-test.thehairnarrative.com'; assert a.lambda_handler(e,None)['isAuthorized'] is False; e['headers']['origin']='https://admin.thehairnarrative.com'; e['requestContext']['stage']='test'; assert a.lambda_handler(e,None)['isAuthorized'] is False"
        result=self.run_profile('production',code)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_test_owner_and_qa_operator_cannot_redirect_to_production_state(self):
        for module in ('tools.provision_thn_owner','auth_admin_owner_operator_v2','auth_admin_qa_operator_v2'):
            result=self.run_profile('production','import '+module)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('TEST owner operator cannot select another deployment profile',result.stderr)
