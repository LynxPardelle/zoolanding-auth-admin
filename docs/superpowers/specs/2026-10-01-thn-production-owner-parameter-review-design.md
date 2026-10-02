# THN production owner operator: parameter-only release

Status: design approved for documentation; implementation and AWS review pending.

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
IAM trust, or effective permissions differ from the reviewed baseline. It must
also require no competing change set or in-progress stack operation.

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
parameters, resources, role trust and IAM simulations. Test the three parameter
overrides against the deployed template locally; translate the SAM template
with the pinned release tooling and compare allowed native resource names.
Exercise offline tests for stale source/baseline, changed or extra parameter,
missing MFA, wrong principal, unrelated native change, replacement, expired
record, and post-execution identity drift. Run the relevant Auth tests and
`actionlint` when available. A local replay must reach a barrier before
`CreateChangeSet`, using captured current AWS responses.

Promote code through `dev → test → main` with exact selectors and green CI,
without running this manual operation automatically. The eventual `review`
and `execute` each require their own authorization under `AGENTS.md`.

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
