import hashlib
import pathlib
import re
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_PATH = REPO_ROOT / "template.yaml"
HANDLER_PATH = REPO_ROOT / "auth_admin_session_v2.py"

ADMIN_ORIGIN = "https://admin-test.thehairnarrative.com"

V2_TABLES = {
    "ThnAuthAdminV2SessionTable": (
        "zoolanding-auth-admin-test-ThnSessionV2",
        True,
    ),
    "ThnAuthAdminV2CurrentUserStateTable": (
        "zoolanding-auth-admin-test-ThnCurrentUserStateV2",
        False,
    ),
    "ThnAuthAdminV2ChallengeTable": (
        "zoolanding-auth-admin-test-ThnChallengeV2",
        True,
    ),
    "ThnAuthAdminV2ThrottleTable": (
        "zoolanding-auth-admin-test-ThnThrottleV2",
        True,
    ),
    "ThnAuthAdminV2AuditTable": (
        "zoolanding-auth-admin-test-ThnAuditV2",
        False,
    ),
}

STATEFUL_V2_RESOURCES = frozenset(
    {
        *V2_TABLES,
        "ThnAuthAdminV2UserPool",
        "ThnAuthAdminV2UserPoolClient",
        "ThnAuthAdminV2OwnerGroup",
        "ThnAuthAdminV2OwnerOperatorFunctionLogGroup",
        "ThnAuthAdminV2FunctionLogGroup",
        "ThnAuthAdminV2ApiAccessLogGroup",
        "ThnAuthAdminV2OriginAuthorizerFunctionLogGroup",
    }
)

EXPECTED_AUTH_ROUTES = {
    ("POST", "/auth-v2/session/signin"),
    ("POST", "/auth-v2/session/challenge/respond"),
    ("POST", "/auth-v2/session/mfa/setup"),
    ("POST", "/auth-v2/session/mfa/verify"),
    ("GET", "/auth-v2/session/me"),
    ("POST", "/auth-v2/session/logout"),
}

FORBIDDEN_DYNAMODB_ACTIONS = {
    "dynamodb:BatchGetItem",
    "dynamodb:BatchWriteItem",
    "dynamodb:DeleteItem",
    "dynamodb:Query",
    "dynamodb:Scan",
}

ALLOWED_COGNITO_ACTIONS = {
    "cognito-idp:AdminGetUser",
    "cognito-idp:AdminInitiateAuth",
    "cognito-idp:AdminListGroupsForUser",
    "cognito-idp:AdminRespondToAuthChallenge",
}


def _template() -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8")


def _mapping_block(text: str, key: str, indent: int) -> str:
    lines = text.splitlines(keepends=True)
    marker = " " * indent + key + ":"
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if line.rstrip("\r\n").rstrip() == marker
        ),
        None,
    )
    if start is None:
        raise AssertionError(f"Missing YAML mapping: {key}")
    end = len(lines)
    sibling = re.compile(rf"^ {{{indent}}}[^ #][^:]*:\s*(?:#.*)?$")
    for index in range(start + 1, len(lines)):
        if sibling.match(lines[index].rstrip("\r\n")):
            end = index
            break
    return "".join(lines[start:end])


def _resource(template: str, logical_id: str) -> str:
    resources = _mapping_block(template, "Resources", 0)
    return _mapping_block(resources, logical_id, 2)


def _parameter(template: str, logical_id: str) -> str:
    parameters = _mapping_block(template, "Parameters", 0)
    return _mapping_block(parameters, logical_id, 2)


def _list_item_with_sid(role: str, sid: str) -> str:
    lines = role.splitlines(keepends=True)
    pattern = re.compile(rf"^(\s*)- Sid:\s*{re.escape(sid)}\s*$")
    for start, line in enumerate(lines):
        match = pattern.match(line.rstrip("\r\n"))
        if not match:
            continue
        indent = len(match.group(1))
        end = len(lines)
        sibling = re.compile(rf"^ {{{indent}}}-\s+")
        for index in range(start + 1, len(lines)):
            candidate = lines[index].rstrip("\r\n")
            if sibling.match(candidate):
                end = index
                break
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) < indent:
                end = index
                break
        return "".join(lines[start:end])
    raise AssertionError(f"Missing IAM statement Sid: {sid}")


def _actions(block: str, service: str) -> set[str]:
    return set(re.findall(rf"- ({re.escape(service)}:[A-Za-z*]+)\s*$", block, re.MULTILINE))


def _referenced_v2_tables(block: str) -> set[str]:
    return {logical_id for logical_id in V2_TABLES if logical_id in block}


def _event_routes(function: str) -> set[tuple[str, str]]:
    events_match = re.search(
        r"(?ms)^      Events:\s*$\n(?P<events>.*?)(?=^      [A-Za-z0-9]+:\s*$|\Z)",
        function,
    )
    if events_match is None:
        raise AssertionError("ThnAuthAdminV2Function is missing Events")
    events = events_match.group("events")
    event_starts = list(re.finditer(r"(?m)^        ([A-Za-z0-9]+):\s*$", events))
    routes: set[tuple[str, str]] = set()
    for index, match in enumerate(event_starts):
        end = event_starts[index + 1].start() if index + 1 < len(event_starts) else len(events)
        event = events[match.start():end]
        method_match = re.search(r"(?m)^            Method:\s*([^\s#]+)", event)
        path_match = re.search(r"(?m)^            Path:\s*([^\s#]+)", event)
        if method_match is None or path_match is None:
            raise AssertionError(f"Malformed HttpApi event: {match.group(1)}")
        routes.add((method_match.group(1).upper(), path_match.group(1)))
    return routes


def _explicit_v2_routes(template: str) -> set[tuple[str, str]]:
    resources = _mapping_block(template, "Resources", 0)
    logical_ids = re.findall(r"(?m)^  ([A-Za-z0-9]+):\s*$", resources)
    routes: set[tuple[str, str]] = set()
    for logical_id in logical_ids:
        block = _resource(template, logical_id)
        if "Type: AWS::ApiGatewayV2::Route" not in block:
            continue
        if "Ref: ThnAuthAdminV2Api" not in block:
            continue
        self_route = re.search(
            r"(?m)^      RouteKey:\s*['\"]?([A-Z]+)\s+([^'\"\s#]+)['\"]?\s*$",
            block,
        )
        if self_route is None:
            raise AssertionError(f"Malformed explicit v2 route: {logical_id}")
        routes.add((self_route.group(1), self_route.group(2)))
    return routes


class AuthAdminV2TemplateContractTests(unittest.TestCase):
    def test_v1_template_contract_stays_exact(self):
        template = _template()
        blocks = [
            _mapping_block(template, "Globals", 0),
            *[
                _parameter(template, logical_id)
                for logical_id in (
                    "EnvironmentName",
                    "AuthAdminConfigJsonBase64",
                    "CognitoUserPoolArns",
                    "LogLevel",
                )
            ],
            *[
                _resource(template, logical_id)
                for logical_id in (
                    "AuthAdminApi",
                    "AuthAdminSessionTable",
                    "AuthAdminUserStateTable",
                    "AuthAdminAuditTable",
                    "AuthAdminFunctionRole",
                    "AuthAdminFunction",
                )
            ],
            _mapping_block(template, "Outputs", 0),
        ]
        normalized = "".join(
            block.replace("\r\n", "\n").rstrip() + "\n" for block in blocks
        ).encode("utf-8")

        # The only approved v1 template change is the exact makefile artifact
        # boundary that packages lambda_function.py alone.
        self.assertEqual(len(normalized), 8_989)
        self.assertEqual(
            hashlib.sha256(normalized).hexdigest(),
            "e608234995909628b04a56c05c17643e67ddc827c22965352403b4cf14a48f2e",
        )

    def test_every_v2_resource_is_test_only_and_fail_closed_by_default(self):
        template = _template()
        resources = _mapping_block(template, "Resources", 0)
        logical_ids = re.findall(r"(?m)^  (ThnAuthAdminV2[A-Za-z0-9]+):\s*$", resources)

        self.assertGreater(len(logical_ids), 10)
        for logical_id in logical_ids:
            with self.subTest(resource=logical_id):
                condition = (
                    "IsThnAuthAdminV2StateProvisioned"
                    if logical_id in STATEFUL_V2_RESOURCES
                    else "IsThnAuthAdminV2Enabled"
                )
                self.assertIn(f"Condition: {condition}", _resource(template, logical_id))

        enabled = _parameter(template, "EnableThnAuthAdminV2")
        provision_state = _parameter(template, "ProvisionThnAuthAdminV2State")
        self.assertIn("Default: 'false'", enabled)
        self.assertNotIn("Default: 'true'", enabled)
        self.assertIn("Default: 'false'", provision_state)
        self.assertNotIn("Default: 'true'", provision_state)

        state_condition = _mapping_block(template, "IsThnAuthAdminV2StateProvisioned", 2)
        self.assertIn("Ref: EnvironmentName", state_condition)
        self.assertIn("- test", state_condition)
        self.assertIn("Ref: ProvisionThnAuthAdminV2State", state_condition)
        self.assertIn("- 'true'", state_condition)
        self.assertNotIn("EnableThnAuthAdminV2", state_condition)

    def test_state_provisioning_and_activation_conditions_are_fail_closed(self):
        template = _template()
        rules = _mapping_block(template, "Rules", 0)
        state_rule = _mapping_block(
            rules,
            "ThnAuthAdminV2StateProvisioningRule",
            2,
        )
        activation_rule = _mapping_block(rules, "ThnAuthAdminV2ActivationRule", 2)
        state_condition = _mapping_block(template, "IsThnAuthAdminV2StateProvisioned", 2)
        enabled_condition = _mapping_block(template, "IsThnAuthAdminV2Enabled", 2)

        self.assertIn("Ref: ProvisionThnAuthAdminV2State", state_rule)
        self.assertIn("Ref: EnvironmentName", state_rule)
        self.assertIn("- test", state_rule)
        self.assertRegex(state_rule, r"(?i)TEST-only")

        self.assertIn("Ref: ProvisionThnAuthAdminV2State", activation_rule)
        self.assertRegex(
            activation_rule,
            r"(?ms)Ref: ProvisionThnAuthAdminV2State\s*\n\s*- 'true'",
        )

        self.assertIn("Fn::And:", state_condition)
        self.assertEqual(state_condition.count("Fn::Equals:"), 2)
        self.assertIn("Ref: EnvironmentName", state_condition)
        self.assertIn("Ref: ProvisionThnAuthAdminV2State", state_condition)

        self.assertIn("Fn::And:", enabled_condition)
        self.assertEqual(enabled_condition.count("Fn::Equals:"), 4)
        for parameter in (
            "EnvironmentName",
            "ProvisionThnAuthAdminV2State",
            "EnableThnAuthAdminV2",
            "ThnAuthAdminV2TerminationProtectionGate",
        ):
            self.assertIn(f"Ref: {parameter}", enabled_condition)

    def test_retained_fixed_name_v2_resources_use_the_non_togglable_state_condition(self):
        template = _template()
        resources = _mapping_block(template, "Resources", 0)
        logical_ids = re.findall(
            r"(?m)^  (ThnAuthAdminV2[A-Za-z0-9]+):\s*$",
            resources,
        )
        retained_fixed_name_resources = []

        for logical_id in logical_ids:
            block = _resource(template, logical_id)
            if "DeletionPolicy: Retain" not in block:
                continue
            if not re.search(
                r"(?m)^\s+(?:TableName|UserPoolName|ClientName|GroupName|LogGroupName):",
                block,
            ):
                continue
            retained_fixed_name_resources.append(logical_id)
            self.assertIn(
                "Condition: IsThnAuthAdminV2StateProvisioned",
                block,
            )
            self.assertNotIn("Condition: IsThnAuthAdminV2Enabled", block)

        self.assertEqual(set(retained_fixed_name_resources), set(STATEFUL_V2_RESOURCES))

    def test_stateful_v2_resources_never_leave_stack_when_routes_are_disabled(self):
        template = _template()

        for logical_id in STATEFUL_V2_RESOURCES:
            with self.subTest(resource=logical_id):
                block = _resource(template, logical_id)
                self.assertIn(
                    "Condition: IsThnAuthAdminV2StateProvisioned",
                    block,
                )
                self.assertNotIn("Condition: IsThnAuthAdminV2Enabled", block)
                self.assertIn("DeletionPolicy: Retain", block)
                self.assertIn("UpdateReplacePolicy: Retain", block)

    def test_declares_five_isolated_retained_encrypted_pitr_tables(self):
        template = _template()

        for logical_id, (table_name, needs_ttl) in V2_TABLES.items():
            with self.subTest(resource=logical_id):
                block = _resource(template, logical_id)
                self.assertRegex(block, r"(?m)^    Type: AWS::DynamoDB::Table\s*$")
                self.assertRegex(block, r"(?m)^    DeletionPolicy: Retain\s*$")
                self.assertRegex(block, r"(?m)^    UpdateReplacePolicy: Retain\s*$")
                self.assertIn(f"TableName: {table_name}", block)
                self.assertRegex(
                    block,
                    r"(?ms)PointInTimeRecoverySpecification:\s*\n"
                    r"\s+PointInTimeRecoveryEnabled: true\s*$",
                )
                self.assertRegex(
                    block,
                    r"(?ms)SSESpecification:\s*\n\s+SSEEnabled: true\s*$",
                )
                self.assertIn("DeletionProtectionEnabled: true", block)
                if needs_ttl:
                    self.assertRegex(
                        block,
                        r"(?ms)TimeToLiveSpecification:\s*\n"
                        r"\s+AttributeName: expiresAt\s*\n\s+Enabled: true\s*$",
                    )

        self.assertNotEqual(
            _resource(template, "ThnAuthAdminV2SessionTable"),
            _resource(template, "AuthAdminSessionTable"),
        )
        self.assertNotEqual(
            _resource(template, "ThnAuthAdminV2CurrentUserStateTable"),
            _resource(template, "AuthAdminUserStateTable"),
        )
        self.assertNotEqual(
            _resource(template, "ThnAuthAdminV2AuditTable"),
            _resource(template, "AuthAdminAuditTable"),
        )

    def test_v2_audit_table_is_reserved_and_session_runtime_has_no_writer(self):
        template = _template()
        audit = _resource(template, "ThnAuthAdminV2AuditTable")
        role = _resource(template, "ThnAuthAdminV2FunctionRole")
        function = _resource(template, "ThnAuthAdminV2Function")

        self.assertIn("DeletionPolicy: Retain", audit)
        self.assertIn("UpdateReplacePolicy: Retain", audit)
        self.assertIn("DeletionProtectionEnabled: true", audit)
        self.assertIn("PointInTimeRecoveryEnabled: true", audit)
        self.assertIn("SSEEnabled: true", audit)
        self.assertRegex(
            audit,
            r"(?ms)KeySchema:\s*\n"
            r"\s+- AttributeName: pk\s*\n\s+KeyType: HASH\s*\n"
            r"\s+- AttributeName: sk\s*\n\s+KeyType: RANGE\s*$",
        )
        deny = _list_item_with_sid(audit, "DenyThnAuthV2AuditMutationAndDeletion")
        self.assertEqual(
            _actions(deny, "dynamodb"),
            {
                "dynamodb:BatchWriteItem",
                "dynamodb:DeleteItem",
                "dynamodb:PartiQLDelete",
                "dynamodb:PartiQLInsert",
                "dynamodb:PartiQLUpdate",
                "dynamodb:UpdateItem",
            },
        )
        self.assertNotIn("Condition:", deny)
        put_deny = _list_item_with_sid(audit, "DenyThnAuthV2AuditPutFromNonMediator")
        self.assertEqual(_actions(put_deny, "dynamodb"), {"dynamodb:PutItem"})
        self.assertIn("ArnNotEquals", put_deny)
        self.assertIn("aws:PrincipalArn", put_deny)
        self.assertIn("zoolanding-auth-admin-test-ThnOwnerOperatorV2Role", put_deny)
        self.assertNotIn("ThnAuthAdminV2AuditTable", role)
        self.assertNotIn("THN_AUTH_V2_AUDIT", function)

    def test_dedicated_cognito_pool_is_admin_created_totp_only_and_retained(self):
        template = _template()
        pool = _resource(template, "ThnAuthAdminV2UserPool")
        client = _resource(template, "ThnAuthAdminV2UserPoolClient")

        self.assertIn("Type: AWS::Cognito::UserPool", pool)
        self.assertIn("DeletionPolicy: Retain", pool)
        self.assertIn("UpdateReplacePolicy: Retain", pool)
        self.assertRegex(
            pool,
            r"(?ms)AdminCreateUserConfig:\s*\n\s+AllowAdminCreateUserOnly: true\s*$",
        )
        self.assertRegex(pool, r"(?m)^      MfaConfiguration: ON\s*$")
        self.assertRegex(
            pool,
            r"(?ms)EnabledMfas:\s*\n\s+- SOFTWARE_TOKEN_MFA\s*$",
        )
        self.assertNotIn("SMS_MFA", pool)
        self.assertRegex(
            pool,
            r"(?ms)RecoveryMechanisms:\s*\n\s+- Name: admin_only\s*\n"
            r"\s+Priority: 1\s*$",
        )
        self.assertIn("DeletionProtection: ACTIVE", pool)

        self.assertIn("Type: AWS::Cognito::UserPoolClient", client)
        self.assertIn("DeletionPolicy: Retain", client)
        self.assertIn("UpdateReplacePolicy: Retain", client)
        self.assertIn("Ref: ThnAuthAdminV2UserPool", client)
        self.assertIn("GenerateSecret: false", client)
        self.assertIn("PreventUserExistenceErrors: ENABLED", client)
        self.assertRegex(
            client,
            r"(?ms)ExplicitAuthFlows:\s*\n\s+- ALLOW_ADMIN_USER_PASSWORD_AUTH\s*$",
        )
        self.assertEqual(
            re.findall(r"(?m)^\s+- (ALLOW_[A-Z_]+)\s*$", client),
            ["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        )
        self.assertIn("AuthSessionValidity: 5", client)
        self.assertNotIn("ALLOW_USER_SRP_AUTH", client)

    def test_dedicated_owner_group_is_exact_and_has_no_shared_role_binding(self):
        group = _resource(_template(), "ThnAuthAdminV2OwnerGroup")

        self.assertIn("Type: AWS::Cognito::UserPoolGroup", group)
        self.assertIn("Condition: IsThnAuthAdminV2StateProvisioned", group)
        self.assertIn("GroupName: journal-owner", group)
        self.assertIn("Ref: ThnAuthAdminV2UserPool", group)
        self.assertNotIn("zoosite", group.lower())
        self.assertNotIn("RoleArn", group)
        self.assertNotIn("Precedence", group)

    def test_owner_operator_policy_is_function_url_only_and_mediator_owns_mutations(self):
        template = _template()
        policy = _resource(template, "ThnAuthAdminV2OwnerOperatorPolicy")
        mediator_role = _resource(template, "ThnAuthAdminV2OwnerOperatorFunctionRole")
        mediator = _resource(template, "ThnAuthAdminV2OwnerOperatorFunction")
        function_url = _resource(
            template,
            "ThnAuthAdminV2OwnerOperatorFunctionUrl",
        )

        self.assertIn("Type: AWS::IAM::Policy", policy)
        self.assertIn("Condition: IsThnAuthAdminV2Enabled", policy)
        self.assertRegex(
            policy,
            r"(?ms)Roles:\s*\n\s+- zoolanding-thn-registry-test-operator\s*$",
        )
        self.assertEqual(
            _actions(policy, "lambda"),
            {
                "lambda:GetFunctionUrlConfig",
                "lambda:InvokeFunction",
                "lambda:InvokeFunctionUrl",
            },
        )
        self.assertIn("lambda:FunctionUrlAuthType", policy)
        self.assertIn("AWS_IAM", policy)
        self.assertIn("lambda:InvokedViaFunctionUrl", policy)
        self.assertFalse(_actions(policy, "cloudformation"))
        self.assertFalse(_actions(policy, "cognito-idp"))
        self.assertFalse(_actions(policy, "dynamodb"))
        self.assertIn("ThnAuthAdminV2OwnerOperatorFunction", policy)
        self.assertIn(":test", policy)
        self.assertNotIn("zoolanding-cognito-user-lifecycle", policy)
        self.assertNotIn("Api", policy)

        self.assertIn("Type: AWS::IAM::Role", mediator_role)
        self.assertEqual(
            _actions(mediator_role, "cloudformation"),
            {"cloudformation:DescribeStackResource"},
        )
        self.assertEqual(
            _actions(mediator_role, "cognito-idp"),
            {
                "cognito-idp:AdminAddUserToGroup",
                "cognito-idp:AdminCreateUser",
                "cognito-idp:AdminDeleteSoftwareToken",
                "cognito-idp:AdminDisableUser",
                "cognito-idp:AdminEnableUser",
                "cognito-idp:AdminGetUser",
                "cognito-idp:AdminListGroupsForUser",
                "cognito-idp:AdminRemoveUserFromGroup",
                "cognito-idp:AdminSetUserPassword",
                "cognito-idp:AdminUserGlobalSignOut",
                "cognito-idp:DescribeUserPool",
                "cognito-idp:DescribeUserPoolClient",
                "cognito-idp:GetGroup",
                "cognito-idp:ListUsersInGroup",
            },
        )
        self.assertEqual(
            _actions(mediator_role, "dynamodb"),
            {"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"},
        )
        self.assertIn("ThnAuthAdminV2CurrentUserStateTable", mediator_role)
        self.assertIn("ThnAuthAdminV2AuditTable", mediator_role)
        self.assertIn("CURRENT_USER#test#thn-journal-test-v2", mediator_role)
        self.assertIn("AUDIT#test#thn-journal-test-v2", mediator_role)
        self.assertNotIn("zoolanding-cognito-user-lifecycle", mediator_role)

        self.assertIn("Type: AWS::Serverless::Function", mediator)
        self.assertIn("Handler: auth_admin_owner_operator_v2.lambda_handler", mediator)
        self.assertIn("AutoPublishAlias: test", mediator)
        self.assertIn("ReservedConcurrentExecutions: 1", mediator)
        self.assertIn("ThnAuthAdminV2OwnerOperatorFunctionRole", mediator)
        self.assertNotIn("Events:", mediator)
        self.assertNotIn("FunctionUrl", mediator)

        self.assertIn("Type: AWS::Lambda::Url", function_url)
        self.assertIn("Condition: IsThnAuthAdminV2Enabled", function_url)
        self.assertIn("AuthType: AWS_IAM", function_url)
        self.assertIn("InvokeMode: BUFFERED", function_url)
        self.assertIn("Qualifier: test", function_url)
        self.assertIn("ThnAuthAdminV2OwnerOperatorFunction", function_url)
        self.assertNotIn("Cors:", function_url)

    def test_owner_mediator_alias_policy_allows_only_signed_function_url_invocation(self):
        policy = _resource(
            _template(),
            "ThnAuthAdminV2OwnerOperatorAliasPolicy",
        )

        self.assertIn("Type: AWS::Lambda::ResourcePolicy", policy)
        self.assertIn("Condition: IsThnAuthAdminV2Enabled", policy)
        self.assertRegex(
            policy,
            r"(?ms)DependsOn:\s*\n\s+- ThnAuthAdminV2OwnerOperatorFunctionAliastest\s*$",
        )
        self.assertGreaterEqual(policy.count(":test"), 5)
        self.assertGreaterEqual(policy.count("lambda:InvokeFunction"), 4)
        self.assertGreaterEqual(policy.count("lambda:InvokeFunctionUrl"), 2)
        deny = _list_item_with_sid(policy, "DenyInvokeFromEveryOtherPrincipal")
        deny_direct = _list_item_with_sid(policy, "DenyDirectInvokeFromEveryPrincipal")
        allow_url = _list_item_with_sid(policy, "AllowFunctionUrlFromNamedOperator")
        allow_invoke = _list_item_with_sid(policy, "AllowInvokeViaFunctionUrlFromNamedOperator")
        self.assertIn("Effect: Deny", deny)
        self.assertIn("Principal: '*'", deny)
        self.assertIn("ArnNotEquals:", deny)
        self.assertIn("aws:PrincipalArn:", deny)
        self.assertIn(
            "role/zoolanding-thn-registry-test-operator",
            deny,
        )
        self.assertIn("lambda:InvokeFunctionUrl", deny)
        self.assertIn("lambda:InvokeFunction", deny)
        self.assertIn("Effect: Deny", deny_direct)
        self.assertIn("BoolIfExists:", deny_direct)
        self.assertIn("lambda:InvokedViaFunctionUrl: 'false'", deny_direct)
        self.assertIn("Effect: Allow", allow_url)
        self.assertIn("lambda:InvokeFunctionUrl", allow_url)
        self.assertIn("lambda:FunctionUrlAuthType", allow_url)
        self.assertIn("AWS_IAM", allow_url)
        self.assertIn("Effect: Allow", allow_invoke)
        self.assertIn("lambda:InvokeFunction", allow_invoke)
        self.assertIn("lambda:InvokedViaFunctionUrl: 'true'", allow_invoke)
        for statement in (allow_url, allow_invoke):
            self.assertIn("AWS:", statement)
            self.assertIn(
                "role/zoolanding-thn-registry-test-operator",
                statement,
            )

    def test_v2_function_and_role_are_separate_and_use_the_v2_handler(self):
        template = _template()
        function = _resource(template, "ThnAuthAdminV2Function")
        role = _resource(template, "ThnAuthAdminV2FunctionRole")

        self.assertIn("Type: AWS::Serverless::Function", function)
        self.assertIn("Handler: auth_admin_session_v2.lambda_handler", function)
        self.assertIn("BuildMethod: makefile", function)
        self.assertIn("Ref: ThnAuthAdminV2UserPool", function)
        self.assertIn("Ref: ThnAuthAdminV2UserPoolClient", function)
        self.assertIn("ThnAuthAdminV2FunctionRole", function)
        self.assertNotIn("Ref: EnvironmentName", function)

        expected_environment = {
            "THN_AUTH_V2_DESCRIPTOR_VERSION_ID": "ThnAuthAdminV2DescriptorVersionId",
            "THN_AUTH_V2_DESCRIPTOR_SHA256": "ThnAuthAdminV2DescriptorSha256",
            "THN_AUTH_V2_AUTH_POLICY_VERSION": "ThnAuthAdminV2AuthPolicyVersion",
            "THN_AUTH_V2_AWS_PARTITION": "AWS::Partition",
            "THN_AUTH_V2_AWS_ACCOUNT_ID": "AWS::AccountId",
            "THN_AUTH_V2_AWS_REGION": "AWS::Region",
            "THN_AUTH_V2_COGNITO_REGION": "AWS::Region",
            "THN_AUTH_V2_COGNITO_USER_POOL_ID": "ThnAuthAdminV2UserPool",
            "THN_AUTH_V2_COGNITO_CLIENT_ID": "ThnAuthAdminV2UserPoolClient",
        }
        for variable, source in expected_environment.items():
            with self.subTest(variable=variable):
                self.assertIn(variable, function)
                self.assertIn(source, function)

        self.assertIn("Type: AWS::IAM::Role", role)
        self.assertIn(
            "RoleName: zoolanding-auth-admin-test-ThnAuthAdminV2FunctionRole",
            role,
        )
        self.assertNotEqual(function, _resource(template, "AuthAdminFunction"))
        self.assertNotEqual(role, _resource(template, "AuthAdminFunctionRole"))

    def test_v2_role_has_exact_table_boundaries_and_no_broad_data_actions(self):
        role = _resource(_template(), "ThnAuthAdminV2FunctionRole")
        all_dynamodb_actions = _actions(role, "dynamodb")
        all_cognito_actions = _actions(role, "cognito-idp")

        self.assertTrue(all_dynamodb_actions)
        self.assertEqual(
            all_dynamodb_actions,
            {
                "dynamodb:ConditionCheckItem",
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
            },
        )
        self.assertFalse(FORBIDDEN_DYNAMODB_ACTIONS & all_dynamodb_actions)
        self.assertNotIn("dynamodb:*", all_dynamodb_actions)
        self.assertNotIn("cognito-idp:*", all_cognito_actions)
        self.assertEqual(all_cognito_actions, ALLOWED_COGNITO_ACTIONS)
        self.assertEqual(
            _actions(role, "logs"),
            {"logs:CreateLogStream", "logs:PutLogEvents"},
        )
        self.assertNotIn("ManagedPolicyArns", role)
        self.assertNotRegex(role, r"(?m)^\s+Resource:\s*['\"]?\*['\"]?\s*$")
        self.assertNotRegex(role, r"(?m)^\s+- (?:dynamodb|logs|cognito-idp):\*\s*$")
        self.assertEqual(
            set(re.findall(r"(?m)^\s+- Sid:\s*([A-Za-z0-9]+)\s*$", role)),
            {
                "ThnAuthV2FunctionLogs",
                "ThnAuthV2CognitoServerAuth",
                "ThnAuthV2RegistryRead",
                "ThnAuthV2SessionRead",
                "ThnAuthV2SessionUpdate",
                "ThnAuthV2SessionTransactionalPut",
                "ThnAuthV2ChallengeRead",
                "ThnAuthV2ChallengeWrite",
                "ThnAuthV2ThrottleRead",
                "ThnAuthV2ThrottleTransactionalPut",
                "ThnAuthV2CurrentUserRead",
                "ThnAuthV2CurrentUserTransactionalCheck",
            },
        )

        cognito = _list_item_with_sid(role, "ThnAuthV2CognitoServerAuth")
        self.assertEqual(_actions(cognito, "cognito-idp"), ALLOWED_COGNITO_ACTIONS)
        self.assertIn("ThnAuthAdminV2UserPool", cognito)
        self.assertNotRegex(cognito, r"(?m)^\s+Resource:\s*['\"]?\*['\"]?\s*$")

        expected_statements = {
            "ThnAuthV2SessionRead": (
                {"dynamodb:GetItem"},
                {"ThnAuthAdminV2SessionTable"},
            ),
            "ThnAuthV2SessionUpdate": (
                {"dynamodb:UpdateItem"},
                {"ThnAuthAdminV2SessionTable"},
            ),
            "ThnAuthV2SessionTransactionalPut": (
                {"dynamodb:PutItem"},
                {"ThnAuthAdminV2SessionTable"},
            ),
            "ThnAuthV2ChallengeRead": (
                {"dynamodb:GetItem"},
                {"ThnAuthAdminV2ChallengeTable"},
            ),
            "ThnAuthV2ChallengeWrite": (
                {"dynamodb:PutItem", "dynamodb:UpdateItem"},
                {"ThnAuthAdminV2ChallengeTable"},
            ),
            "ThnAuthV2ThrottleRead": (
                {"dynamodb:GetItem"},
                {"ThnAuthAdminV2ThrottleTable"},
            ),
            "ThnAuthV2ThrottleTransactionalPut": (
                {"dynamodb:PutItem"},
                {"ThnAuthAdminV2ThrottleTable"},
            ),
        }
        for sid, (actions, tables) in expected_statements.items():
            with self.subTest(sid=sid):
                statement = _list_item_with_sid(role, sid)
                self.assertEqual(_actions(statement, "dynamodb"), actions)
                self.assertEqual(_referenced_v2_tables(statement), tables)

        for sid in (
            "ThnAuthV2SessionTransactionalPut",
            "ThnAuthV2ThrottleTransactionalPut",
        ):
            self.assertIn(
                "dynamodb:EnclosingOperation: TransactWriteItems",
                _list_item_with_sid(role, sid),
            )

        current_user = _list_item_with_sid(role, "ThnAuthV2CurrentUserRead")
        self.assertEqual(_actions(current_user, "dynamodb"), {"dynamodb:GetItem"})
        self.assertEqual(
            _referenced_v2_tables(current_user),
            {"ThnAuthAdminV2CurrentUserStateTable"},
        )
        self.assertIn("CURRENT_USER#test#thn-journal-test-v2", current_user)

        current_user_check = _list_item_with_sid(
            role, "ThnAuthV2CurrentUserTransactionalCheck"
        )
        self.assertEqual(
            _actions(current_user_check, "dynamodb"),
            {"dynamodb:ConditionCheckItem"},
        )
        self.assertEqual(
            _referenced_v2_tables(current_user_check),
            {"ThnAuthAdminV2CurrentUserStateTable"},
        )
        self.assertIn("CURRENT_USER#test#thn-journal-test-v2", current_user_check)
        self.assertIn(
            "dynamodb:EnclosingOperation: TransactWriteItems",
            current_user_check,
        )

        self.assertNotIn("ThnAuthV2AuditAppend", role)
        self.assertNotIn("ThnAuthAdminV2AuditTable", role)

        registry = _list_item_with_sid(role, "ThnAuthV2RegistryRead")
        self.assertEqual(_actions(registry, "dynamodb"), {"dynamodb:GetItem"})
        self.assertIn("zoolanding-content-hub-test-ServiceBindingRegistryV2", registry)
        self.assertIn("SERVICE_BINDING#test#thn-journal-test-v2", registry)
        self.assertFalse(_referenced_v2_tables(registry))

    def test_v2_api_cors_and_routes_are_exact_and_never_fall_back_to_v1(self):
        template = _template()
        api = _resource(template, "ThnAuthAdminV2Api")
        function = _resource(template, "ThnAuthAdminV2Function")

        self.assertIn("Type: AWS::Serverless::HttpApi", api)
        self.assertRegex(api, r"(?m)^      StageName: test\s*$")
        # Managed HTTP API CORS auto-answers preflight before the handler and can
        # accidentally widen the exact route inventory. The protected UI and API
        # are same-origin; the Lambda returns the one approved origin explicitly.
        self.assertNotIn("CorsConfiguration", api)
        self.assertNotIn("DefinitionBody", api)
        self.assertNotIn("DefinitionUri", api)

        self.assertNotIn("Events:", function)
        self.assertEqual(_explicit_v2_routes(template), EXPECTED_AUTH_ROUTES)
        self.assertNotIn("/auth-v2/runtime-config", function)
        self.assertNotIn("/{proxy+}", function)
        self.assertNotRegex(function, r"(?m)^\s+Path: /auth/")
        self.assertNotIn("AuthAdminApi", function.replace("ThnAuthAdminV2Api", ""))

        integration = _resource(template, "ThnAuthAdminV2Integration")
        self.assertIn("Type: AWS::ApiGatewayV2::Integration", integration)
        self.assertIn("Ref: ThnAuthAdminV2Api", integration)
        self.assertIn("ThnAuthAdminV2Function", integration)
        self.assertNotIn("AuthAdminFunction", integration.replace("ThnAuthAdminV2Function", ""))
        self.assertIn("PayloadFormatVersion: '2.0'", integration)

        resources = _mapping_block(template, "Resources", 0)
        route_ids = re.findall(r"(?m)^  ([A-Za-z0-9]+):\s*$", resources)
        route_blocks = [
            _resource(template, logical_id)
            for logical_id in route_ids
            if "Type: AWS::ApiGatewayV2::Route" in _resource(template, logical_id)
            and "Ref: ThnAuthAdminV2Api" in _resource(template, logical_id)
        ]
        self.assertEqual(len(route_blocks), len(EXPECTED_AUTH_ROUTES))
        for route in route_blocks:
            self.assertIn("Ref: ThnAuthAdminV2Integration", route)
            self.assertIn("AuthorizationType: CUSTOM", route)
            self.assertIn("Ref: ThnAuthAdminV2OriginAuthorizer", route)
            self.assertNotIn("AuthorizationType: NONE", route)
            self.assertNotIn("$default", route)

        authorizer = _resource(template, "ThnAuthAdminV2OriginAuthorizer")
        self.assertIn("Type: AWS::ApiGatewayV2::Authorizer", authorizer)
        self.assertIn("AuthorizerType: REQUEST", authorizer)
        self.assertIn("AuthorizerPayloadFormatVersion: '2.0'", authorizer)
        self.assertIn("EnableSimpleResponses: true", authorizer)
        self.assertIn("AuthorizerResultTtlInSeconds: 0", authorizer)
        self.assertIn("$request.header.x-zlp-origin-verify", authorizer)

        authorizer_function = _resource(
            template, "ThnAuthAdminV2OriginAuthorizerFunction"
        )
        self.assertIn(
            "Handler: auth_admin_origin_authorizer_v2.lambda_handler",
            authorizer_function,
        )
        self.assertIn(
            "THN_AUTH_V2_ORIGIN_HEADER_SHA256_CURRENT",
            authorizer_function,
        )
        self.assertIn(
            "THN_AUTH_V2_ORIGIN_HEADER_SHA256_PREVIOUS",
            authorizer_function,
        )

        activation_rule = _mapping_block(template, "Rules", 0)
        self.assertIn("ThnAuthAdminV2OriginHeaderSha256Current", activation_rule)
        self.assertIn("A reviewed origin-proof digest is required", activation_rule)
        self.assertIn("ThnAuthAdminV2OriginHeaderSha256Previous", activation_rule)
        self.assertIn("Origin-proof rotation digests must be distinct", activation_rule)

        permission_blocks = [
            _resource(template, logical_id)
            for logical_id in route_ids
            if "Type: AWS::Lambda::Permission" in _resource(template, logical_id)
            and "ThnAuthAdminV2Function" in _resource(template, logical_id)
        ]
        self.assertEqual(len(permission_blocks), len(EXPECTED_AUTH_ROUTES))
        permission_suffixes = {
            match.group(1)
            for block in permission_blocks
            for match in [
                re.search(
                    r"\$\{ThnAuthAdminV2Api\}/test/([A-Z]+/auth-v2/session/[^\s]+)",
                    block,
                )
            ]
            if match is not None
        }
        self.assertEqual(
            permission_suffixes,
            {f"{method}{path}" for method, path in EXPECTED_AUTH_ROUTES},
        )
        for permission in permission_blocks:
            self.assertIn("Ref: ThnAuthAdminV2Function", permission)
            self.assertIn("Principal: apigateway.amazonaws.com", permission)
            self.assertNotIn("${ThnAuthAdminV2Api}/*", permission)

        handler = HANDLER_PATH.read_text(encoding="utf-8")
        self.assertIn('ADMIN_HOST = "admin-test.thehairnarrative.com"', handler)
        self.assertIn("_require_admin_origin(event)", handler)
        self.assertIn('"x-forwarded-host"', handler)
        self.assertNotIn('"/auth-v2/runtime-config"', handler)
        self.assertNotIn("def _runtime_config_response", handler)
        self.assertIn('"access-control-allow-origin": ADMIN_ORIGIN', handler)
        self.assertIn('"access-control-allow-credentials": "true"', handler)

    def test_v2_errors_and_throttles_have_dedicated_lambda_alarms(self):
        template = _template()
        expected = {
            "ThnAuthAdminV2ErrorsAlarm": "Errors",
            "ThnAuthAdminV2ThrottlesAlarm": "Throttles",
            "ThnAuthAdminV2OwnerOperatorErrorsAlarm": "Errors",
        }
        for logical_id, metric in expected.items():
            with self.subTest(alarm=logical_id):
                alarm = _resource(template, logical_id)
                self.assertIn("Type: AWS::CloudWatch::Alarm", alarm)
                self.assertIn("Namespace: AWS/Lambda", alarm)
                self.assertIn(f"MetricName: {metric}", alarm)
                function = (
                    "ThnAuthAdminV2OwnerOperatorFunction"
                    if logical_id == "ThnAuthAdminV2OwnerOperatorErrorsAlarm"
                    else "ThnAuthAdminV2Function"
                )
                self.assertIn(f"Ref: {function}", alarm)
                self.assertIn("TreatMissingData: notBreaching", alarm)

        api_alarm = _resource(template, "ThnAuthAdminV2Api5xxAlarm")
        self.assertIn("Type: AWS::CloudWatch::Alarm", api_alarm)
        self.assertIn("Namespace: AWS/ApiGateway", api_alarm)
        self.assertIn("MetricName: 5xx", api_alarm)
        self.assertIn("Ref: ThnAuthAdminV2Api", api_alarm)
        self.assertIn("TreatMissingData: notBreaching", api_alarm)

    def test_v2_private_physical_ids_are_not_exported(self):
        template = _template()
        outputs = _mapping_block(template, "Outputs", 0)

        private_logical_ids = set(V2_TABLES) | {
            "ThnAuthAdminV2UserPool",
            "ThnAuthAdminV2UserPoolClient",
            "ThnAuthAdminV2OwnerGroup",
            "ThnAuthAdminV2Function",
            "ThnAuthAdminV2FunctionRole",
        }
        for logical_id in private_logical_ids:
            with self.subTest(resource=logical_id):
                self.assertNotIn(logical_id, outputs)
        self.assertNotRegex(outputs, r"(?i)ThnAuthAdminV2.*(?:Arn|Id|Name)")
        for physical_name, _ in V2_TABLES.values():
            self.assertNotIn(physical_name, outputs)

    def test_v2_logs_are_retained_bounded_and_do_not_capture_request_data(self):
        template = _template()
        function_logs = _resource(template, "ThnAuthAdminV2FunctionLogGroup")
        api_logs = _resource(template, "ThnAuthAdminV2ApiAccessLogGroup")
        api = _resource(template, "ThnAuthAdminV2Api")

        for block in (function_logs, api_logs):
            self.assertIn("Type: AWS::Logs::LogGroup", block)
            self.assertIn("DeletionPolicy: Retain", block)
            self.assertIn("UpdateReplacePolicy: Retain", block)
            self.assertIn("RetentionInDays: 30", block)

        self.assertIn("AccessLogSettings", api)
        self.assertEqual(api.count("DestinationArn:"), 1)
        self.assertIn("$context.requestId", api)
        self.assertIn("$context.routeKey", api)
        for forbidden in (
            "$context.identity.sourceIp",
            "$context.requestOverride.header",
            "$context.error.message",
            "$context.authorizer",
            "cookie",
            "queryString",
        ):
            self.assertNotIn(forbidden, api)
        self.assertIn("DetailedMetricsEnabled: true", api)
        self.assertIn("ThrottlingBurstLimit: 10", api)
        self.assertIn("ThrottlingRateLimit: 5", api)

    def test_termination_protection_uses_a_documented_fail_closed_deploy_gate(self):
        template = _template()
        enabled = _parameter(template, "EnableThnAuthAdminV2")
        gate = _parameter(template, "ThnAuthAdminV2TerminationProtectionGate")
        metadata = _mapping_block(template, "Metadata", 0)
        resources = _mapping_block(template, "Resources", 0)

        self.assertIn("Default: 'false'", enabled)
        self.assertIn("Default: BLOCKED", gate)
        self.assertRegex(
            gate,
            r"(?ms)AllowedValues:\s*\n\s+- BLOCKED\s*\n\s+- CONFIRMED_ENABLED\s*$",
        )
        self.assertRegex(gate, r"(?i)termination protection")
        self.assertRegex(gate, r"(?i)fail[- ]closed|block")

        guard = _mapping_block(metadata, "ThnAuthAdminV2DeploymentGuards", 2)
        self.assertRegex(guard, r"(?i)termination protection")
        self.assertIn("GateParameter: ThnAuthAdminV2TerminationProtectionGate", guard)
        self.assertRegex(guard, r"(?m)^\s+Required: true\s*$")
        self.assertRegex(guard, r"(?m)^\s+FailureMode: BLOCK\s*$")
        self.assertRegex(guard, r"(?i)preflight|deployment workflow")
        self.assertIn("DefaultState: BLOCKED", guard)

        # Stack termination protection is set through the CloudFormation API,
        # not through an invented SAM resource property.
        self.assertNotIn("EnableTerminationProtection:", template)
        self.assertNotRegex(resources, r"(?m)^\s{4,}TerminationProtection:\s*")


if __name__ == "__main__":
    unittest.main()
