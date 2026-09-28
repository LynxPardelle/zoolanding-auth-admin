"""Production operator is a distinct account lifecycle and excludes QA."""
import ast
import os
from pathlib import Path
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
class ProductionOwnerTests(unittest.TestCase):
    def run_owner(self,code,environment='production'):
        return subprocess.run([sys.executable,'-c',code],cwd=ROOT,env={**os.environ,'THN_DEPLOYMENT_ENVIRONMENT':environment},text=True,capture_output=True)
    def test_production_core_rejects_test_profile(self):
        result=self.run_owner('from tools import provision_thn_production_owner','test')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('production owner operator',result.stderr.lower())
    def test_exact_resources_and_no_qa_operations(self):
        code="from tools import provision_thn_production_owner as p; assert p.APPROVED_POOL_NAME=='zoolanding-auth-admin-prod-ThnAuthAdminV2'; assert p.APPROVED_MEDIATOR_FUNCTION=='zoolanding-auth-admin-prod-ThnProductionOwnerOperatorV2'; assert p.APPROVED_MEDIATOR_QUALIFIER=='production'; assert p.APPROVED_SCOPE['environment']=='production'; assert not any(x.startswith('qa-') for x in p._SAFE_OPERATIONS)"
        r=self.run_owner(code);self.assertEqual(r.returncode,0,r.stderr)
    def test_named_production_role_only(self):
        code="from tools import provision_thn_production_owner as p; assert p.require_named_operator('arn:aws:sts::765932874577:assumed-role/zoolanding-thn-owner-production-operator/interactive')=='arn:aws:iam::765932874577:role/zoolanding-thn-owner-production-operator'"
        r=self.run_owner(code);self.assertEqual(r.returncode,0,r.stderr)
        for arn in ('arn:aws:sts::765932874577:assumed-role/zoolanding-thn-registry-test-operator/local','arn:aws:sts::123456789012:assumed-role/zoolanding-thn-owner-production-operator/local'):
            r=self.run_owner('from tools import provision_thn_production_owner as p; p.require_named_operator('+repr(arn)+')');self.assertNotEqual(r.returncode,0)
    def test_mediator_rejects_qa_and_unknown_fields_before_aws(self):
        code="import auth_admin_production_owner_operator_v2 as p; p._new_session=lambda: (_ for _ in ()).throw(AssertionError('AWS must not be called')); r=p.lambda_handler({'contractVersion':1,'operation':'qa-create','username':'owner@example.invalid'},None); assert r['statusCode']==400"
        r=self.run_owner(code);self.assertEqual(r.returncode,0,r.stderr)
    def test_audited_lifecycle_functions_preserve_reviewed_algorithm(self):
        old=ast.parse((ROOT/'tools/provision_thn_owner.py').read_text())
        new=ast.parse((ROOT/'tools/provision_thn_production_owner.py').read_text())
        originals={n.name:ast.dump(n,include_attributes=False) for n in old.body if isinstance(n,ast.FunctionDef)}
        candidates={n.name:ast.dump(n,include_attributes=False) for n in new.body if isinstance(n,ast.FunctionDef)}
        for name in ('discover_dedicated_resources','execute_operation','_audit_event','_safe_result','_require_group_available','_require_exact_user_group'):
            self.assertEqual(candidates[name],originals[name],name)
    def test_production_artifact_excludes_test_tools_and_qa_mutators(self):
        from tools.build_lambda_artifact import SOURCE_ALLOWLIST
        files=set(SOURCE_ALLOWLIST['ThnProductionOwnerOperatorV2Function'])
        self.assertEqual(files,{'thn_environment_profile.py','auth_admin_current_user_v2.py','auth_admin_production_owner_operator_v2.py','tools/provision_thn_production_owner.py'})

    def test_production_replays_secure_discovery_and_lifecycle_regressions(self):
        # The original semantic fixtures are projected only to distinct production
        # names and import the actual production implementation; no AWS is used.
        code="""
from pathlib import Path
import unittest
source=Path('tests/test_provision_thn_owner.py').read_text()
source=source.replace('from tools import provision_thn_owner as owner','from tools import provision_thn_production_owner as owner')
for old,new in {'zoolanding-auth-admin-test-ThnAuthAdminV2':'zoolanding-auth-admin-prod-ThnAuthAdminV2','zoolanding-auth-admin-test-ThnOwnerOperatorV2:test':'zoolanding-auth-admin-prod-ThnProductionOwnerOperatorV2:production','zoolanding-thn-registry-test-operator':'zoolanding-thn-owner-production-operator','zoolanding-auth-admin-test':'zoolanding-auth-admin-prod'}.items(): source=source.replace(old,new)
namespace={'__name__':'production_owner_regression','__file__':str(Path('tests/test_provision_thn_owner.py').resolve())}
exec(compile(source,namespace['__file__'],'exec'),namespace)
suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(namespace[name]) for name in ('ThnOwnerDiscoveryTests','ThnOwnerMutationTests'))
result=unittest.TextTestRunner().run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
"""
        result=self.run_owner(code)
        self.assertEqual(result.returncode,0,result.stderr)
