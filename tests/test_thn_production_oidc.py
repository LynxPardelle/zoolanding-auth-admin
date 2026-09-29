"""Production OIDC uses AWS standard claims and a live main-only environment."""
import copy
import json
import unittest
from unittest.mock import patch, Mock
from tools import run_thn_production_release as driver
from tools.thn_production_release import ReleaseError

class ProductionOidcTests(unittest.TestCase):
    def fixture(self):
        repo = driver.CONFIG['repository']
        return ({'name': 'production', 'html_url': f'https://github.com/LynxPardelle/{repo}/deployments/activity_log?environments_filter=production',
                 'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True}},
                {'total_count': 1, 'branch_policies': [{'id': 1, 'name': 'main', 'type': 'branch'}]})

    def test_live_environment_read_is_anchored_and_incomplete_or_widened_rules_fail(self):
        env, rules = self.fixture()
        repo = driver.CONFIG['repository']
        with patch.object(driver.subprocess, 'run', side_effect=[Mock(stdout=json.dumps(env)), Mock(stdout=json.dumps(rules))]) as command:
            proof = driver.production_environment()
        self.assertEqual(proof['branch'], 'main')
        self.assertEqual(command.call_args_list[0].args[0][2], f'repos/LynxPardelle/{repo}/environments/production')
        self.assertEqual(command.call_args_list[1].args[0][2], f'repos/LynxPardelle/{repo}/environments/production/deployment-branch-policies?per_page=100&page=1')
        for mutation in ('none', 'missing', 'protected', 'tag', 'wildcard', 'duplicate', 'truncated', 'wrong-repo', 'wrong-environment'):
            e, r = copy.deepcopy(env), copy.deepcopy(rules)
            if mutation == 'missing': e['deployment_branch_policy'] = None
            elif mutation == 'protected': e['deployment_branch_policy']['protected_branches'] = True
            elif mutation == 'tag': r['branch_policies'][0]['type'] = 'tag'
            elif mutation == 'wildcard': r['branch_policies'][0]['name'] = '*'
            elif mutation == 'duplicate': r['branch_policies'] *= 2
            elif mutation == 'truncated': r['total_count'] = 2
            elif mutation == 'wrong-repo': e['html_url'] = e['html_url'].replace(repo, 'other-repo')
            elif mutation == 'wrong-environment': e['name'] = 'test'
            with self.subTest(mutation=mutation), patch.object(driver.subprocess, 'run', side_effect=[Mock(stdout=json.dumps(e)), Mock(stdout=json.dumps(r))]):
                if mutation == 'none': driver.production_environment()
                else:
                    with self.assertRaises(ReleaseError): driver.production_environment()

    def test_standard_trust_rejects_unsupported_claims_and_subject_broadening(self):
        repo = driver.CONFIG['repository']
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRoleWithWebIdentity',
            'Principal': {'Federated': 'arn:aws:iam::765932874577:oidc-provider/token.actions.githubusercontent.com'},
            'Condition': {'StringEquals': {'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
                'token.actions.githubusercontent.com:sub': f'repo:LynxPardelle/{repo}:environment:production'}}}]}
        driver.validate_github_trust(trust)
        for mutation in ('ref', 'ifexists', 'aud', 'sub', 'extra-statement', 'principal'):
            bad = copy.deepcopy(trust); s = bad['Statement'][0]
            if mutation == 'ref': s['Condition']['StringEquals']['token.actions.githubusercontent.com:ref'] = 'refs/heads/main'
            elif mutation == 'ifexists': s['Condition']['StringEqualsIfExists'] = s['Condition'].pop('StringEquals')
            elif mutation == 'aud': s['Condition']['StringEquals']['token.actions.githubusercontent.com:aud'] = '*'
            elif mutation == 'sub': s['Condition']['StringEquals']['token.actions.githubusercontent.com:sub'] = f'repo:LynxPardelle/{repo}:ref:refs/heads/main'
            elif mutation == 'extra-statement': bad['Statement'].append(copy.deepcopy(s))
            elif mutation == 'principal': s['Principal']['AWS'] = '*'
            with self.subTest(mutation=mutation), self.assertRaises(ReleaseError): driver.validate_github_trust(bad)

    def test_source_selection_seals_remote_environment_before_credentials(self):
        from pathlib import Path
        source = (Path(driver.__file__)).read_text()
        body = source.split('def source_selection(', 1)[1].split('CALLER_ACTIONS=', 1)[0]
        self.assertIn('production_environment()', body)
        workflow = (driver.ROOT/'.github/workflows/deploy-thn-production.yml').read_text()
        self.assertLess(workflow.index('Recheck current main immediately before credentials'), workflow.index('Assume selected production deployment identity'))

    def test_source_authority_rejects_wrong_repository_branch_event_or_remote_sha(self):
        import os
        environment,rules=self.fixture()
        authority={'GITHUB_REPOSITORY':f'LynxPardelle/{driver.CONFIG["repository"]}',
                   'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch'}
        for mutation in ('none','repository','branch','event','remote-main','unprotected'):
            values=dict(authority)
            if mutation=='repository':values['GITHUB_REPOSITORY']='other/repo'
            elif mutation=='branch':values['GITHUB_REF']='refs/heads/dev'
            elif mutation=='event':values['GITHUB_EVENT_NAME']='push'
            def command(args,**kwargs):
                if args[0]=='git':return Mock(stdout=('b'*40 if args[-1]=='HEAD^{tree}' else 'a'*40))
                if '/git/ref/heads/main' in args[2]:return Mock(stdout=('c'*40 if mutation=='remote-main' else 'a'*40))
                if 'deployment-branch-policies' in args[2]:return Mock(stdout=json.dumps(rules))
                result=copy.deepcopy(environment)
                if mutation=='unprotected':result['deployment_branch_policy']=None
                return Mock(stdout=json.dumps(result))
            with self.subTest(mutation=mutation),patch.dict(os.environ,values),patch.object(driver.subprocess,'run',side_effect=command):
                if mutation=='none':self.assertEqual(driver.source_selection('a'*40)['productionEnvironment']['branch'],'main')
                else:
                    with self.assertRaises(ReleaseError):driver.source_selection('a'*40)
