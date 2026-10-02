# THN production owner operator: parameter-only release

Status: IAM prerequisite added after read-only preflight; revised written design
awaits user review. No implementation or AWS review has run for this change.

## Evidence and purpose

The protected `zoolanding-auth-admin-prod` stack is `UPDATE_COMPLETE`. Its
deployed Original template already contains the eight conditional owner operator
resources. The stack currently has 37 physical resources and no owner operator
resource. Its deployed Processed template expands those eight resources to ten;
the function version logical ID is
`ThnProductionOwnerOperatorV2FunctionVersion70edfefcc3`. This deployed ID,
rather than a generated manifest from a different build, is authoritative for
the parameter-only transition. `ProvisionThnAuthAdminV2State=true`, while
`ProvisionThnProductionOwnerOperatorV2=false`,
`ThnProductionOwnerOperatorGate=BLOCKED`,
`ThnProductionOwnerHumanPrincipalArn=BLOCKED`, and
`EnableThnAuthAdminV2=false`. The proposed human principal is the exact
`arn:aws:iam::765932874577:user/Hector-admin`: AWS reports one MFA device, and
its identity policy simulation allows `sts:AssumeRole` on the proposed operator
role with MFA present and age 120 seconds. The role does not exist yet.

The current `state` workflow builds and uploads packages for every SAM
function. That can change existing function code coordinates during an owner
operator review even if their bytes are identical. This operation instead
reuses the deployed template. AWS documents `UsePreviousTemplate=true` for
parameter-only change sets. Its caution applies to
`AWS::LanguageExtensions`; the deployed Auth template has only
`AWS::Serverless-2016-10-31`.

The live IAM preflight found a separate blocker in the Auth GitHub deployment
role, `zoolanding-auth-admin-production-deploy`. CloudFormation's execution
role has `allowed` for all 97 required native action/resource pairs for the ten
owner additions, but the GitHub role returns `implicitDeny` for several reads
needed to establish and verify the owner baseline. Launching an Auth review
before fixing these exact reads would produce another predictable failed run.

## Prerequisite: scoped deployment-role reads

First add a dedicated `auth-owner-read-patch` operation to the protected
production deployment-identities release in `zoolandingpage-aws-infra`. Its
candidate is derived from the deployed identities template and may modify only
the `PolicyDocument` of `AuthGithubReleasePolicy`, attached to
`zoolanding-auth-admin-production-deploy`. Add only these reads, with exact
resource ARNs in account `765932874577` and region `us-east-1`:

- `iam:ListMFADevices` on `arn:aws:iam::765932874577:user/Hector-admin`.
- `cognito-idp:ListUsersInGroup` on the production user pool
  `arn:aws:cognito-idp:us-east-1:765932874577:userpool/us-east-1_c1QxYjOiI`.
- `iam:GetRole`, `iam:GetRolePolicy`, `iam:ListRolePolicies`, and
  `iam:ListAttachedRolePolicies` on the owner human role
  `arn:aws:iam::765932874577:role/zoolanding-thn-owner-production-operator`
  and owner Lambda role
  `arn:aws:iam::765932874577:role/zoolanding-auth-admin-prod-ThnProductionOwnerOperatorV2Role`.
- `lambda:GetAlias` and `lambda:GetFunctionUrlConfig` on the exact owner
  function `arn:aws:lambda:us-east-1:765932874577:function:zoolanding-auth-admin-prod-ThnProductionOwnerOperatorV2`
  and its `production` qualified ARN, only as required by the actual API calls.
- `cloudformation:ListChangeSets` on the Auth stack
  `arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-auth-admin-prod/*`.

The implementation must validate AWS's resource-level authorization semantics
for each action before finalizing the statements. If an action cannot be
restricted to the stated resource, do not silently replace it with `*`;
rework the preflight or bring that exception back for review. Preserve every
existing statement, condition, attached role, and resource in the policy.
Do not add write actions, Cognito mutation, Lambda invocation, or human-role
permissions. No owner resource or route is created by this prerequisite.

The new identities scope must pass all workflow, shared operation, source
package, and inventory allowlists. A local replay with captured AWS responses
must reach the barrier immediately before its first write. Its AWS `review`
creates and inspects a temporary change set; accept exactly one `Modify`
without replacement of `AuthGithubReleasePolicy` and no other resource change.
Show the inventory and digest, then require separate authorization for
`execute`. After execution, verify the policy document and repeat
`SimulatePrincipalPolicy` on every previously denied exact action/resource
pair. Require all of them to be `allowed` before dispatching the Auth owner
review. Stop on drift or an unexpected inventory instead of retrying an Action.

## Decision and boundaries

Add a dedicated manual production workflow and a small operator for this one
parameter-only transition. Keep the existing retained release path unchanged.
The workflow runs only from the exact current `main` SHA in the protected
`production` Environment with the existing Auth OIDC deployment role. It has
`review` and `execute` operations and no build, `sam package`, S3 package
write, Cognito mutation, or owner enrollment step.

Review calls `CreateChangeSet` on the existing Auth stack with
`UsePreviousTemplate=true`, the current CloudFormation execution role,
`CAPABILITY_NAMED_IAM`, and the current tags. It supplies exactly these three
new values:

- `ProvisionThnProductionOwnerOperatorV2=true`
- `ThnProductionOwnerOperatorGate=CONFIRMED_PRODUCTION_OWNER_OPERATOR`
- `ThnProductionOwnerHumanPrincipalArn=arn:aws:iam::765932874577:user/Hector-admin`

Every other parameter must use its previous value, including masked NoEcho
parameters. `EnableThnAuthAdminV2` remains `false`. The workflow must fail
before creating the change set if the stack, deployed Original and Processed
templates, parameter set, production identity, MFA device, protected branch,
IAM trust, or effective permissions differ from the reviewed baseline. The
prerequisite read policy must already be deployed and every required read must
simulate as `allowed`. It must also require no competing change set or
in-progress stack operation.

## Inventory and approval

After creating the change set, read every page of the native change inventory
and both change-set templates. Permit only `Add` without replacement for the
eight owner logical IDs already gated by
`IsThnProductionOwnerOperatorV2Provisioned` and the SAM-generated owner
function version and `production` alias. The complete allowed logical-ID set
must be derived from and pinned to the current deployed Processed template,
including its exact generated version suffix; the review must not assume that
a fresh SAM build produces the same suffix. Reject every `Modify`, `Remove`,
replacement, or addition outside that list. In particular, any change to an
existing Auth function, API route, Cognito pool or group, table, or policy
outside the operator aborts the review and deletes its temporary change set.
The record must include a digest over the exact
source SHA, stack ID, template and parameter fingerprints, IAM proof, change
set ARN, and full sanitized inventory. Keep no passwords or MFA material in
the record. The approved record expires after 24 hours.

Present the complete inventory and digest to the user. Execution requires
separate authorization for that exact digest. Before `ExecuteChangeSet`, fetch
the review run and record, compare current `main`, stack, parameters, templates,
identity, permissions, and change set again, and reject expiry or any mismatch.
After execution, verify `UPDATE_COMPLETE`, termination protection, unchanged
physical IDs of all 37 prior resources, only the approved new owner resources,
the exact MFA-conditioned human role trust, the mediator function URL's
`AWS_IAM` authorization, and `EnableThnAuthAdminV2=false`. Confirm
`journal-owner` still has zero users. Do not call the owner mediator.

If the change set fails to create, has an unexpected resource, or execution
rolls back, stop and diagnose the recorded event and current stack state.
Never auto-delete retained resources or retry the operation blindly.

## Checks before the first Action

Use AWS CLI to refresh the protected stack, Original and Processed templates,
parameters, resources, role trust and IAM simulations. The current native
provider-schema selection yielded 97/97 allowed pairs for the CloudFormation
execution role; repeat that proof if the template or execution role changes.
Confirm the identities stack and deployed `AuthGithubReleasePolicy` before the
IAM patch, and simulate its newly allowed reads after the separately approved
execution. Test the three parameter overrides against the deployed template
locally; translate the SAM template
with the pinned release tooling and compare allowed native resource names.
Exercise offline tests for stale source/baseline, changed or extra parameter,
missing MFA, wrong principal, unrelated native change, replacement, expired
record, and post-execution identity drift. Run the relevant Auth tests and
`actionlint` when available. A local replay must reach a barrier before
`CreateChangeSet`, using captured current AWS responses.

Promote the identities patch code through `dev → test → main` with exact
selectors and green CI, without invoking AWS automatically. Review and execute
the identities patch only with separate approvals. Then promote the Auth owner
operation code through the same branch sequence. Its eventual `review` and
`execute` each require their own authorization under `AGENTS.md`.

## Alternatives and acceptance

The existing `state` release is unsuitable for this narrow transition because
it repackages other functions. Direct CLI execution has no durable source,
inventory, and digest guard. The dedicated parameter-only path minimizes the
resources touched while keeping a reviewable release record.

The operation is accepted when its protected review shows only the intended
owner additions, its separately approved execution preserves all existing
resource identities and closed routes, and the operator can be assumed only
by the approved MFA-protected human principal. Creating the client account,
enrolling TOTP, and opening authoring routes remain separate steps.

AWS API reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html
