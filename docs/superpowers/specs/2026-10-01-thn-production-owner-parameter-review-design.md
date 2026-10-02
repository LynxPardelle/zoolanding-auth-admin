# THN production owner operator: parameter-only release

Status: Template-body amendment drafted after the 2026-10-02 review failure;
awaiting user review. The owner operation has not been executed in AWS.

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
reuses the exact deployed Original template and package coordinates. The
deployed Auth template has only `AWS::Serverless-2016-10-31`.

The first protected owner review on MAIN
`7123cd8e4c222343bd6a09d7d999583334b534cf`, run
[#37071052433](https://github.com/LynxPardelle/zoolanding-auth-admin/actions/runs/37071052433),
used `UsePreviousTemplate=true`. It passed source validation, OIDC assumption,
IAM and stack preflight, and created a change set. The preview guard then
reported `production_owner_transform_invalid` while comparing its Original and
Processed templates. The guard deleted that change set; the stack remains
protected and `UPDATE_COMPLETE` with 37 resources, no pending change set, and
the owner gate still off. Fresh `GetTemplate` calls confirm the stack Original
has the single SAM transform and Processed has none. Therefore the mismatch
was in the change-set view. Reuse of the processed template is the likely
cause, but the failed run did not retain the two change-set template bodies,
so the exact returned shape is unconfirmed. Do not retry the same request.

The exact deployed Original template serializes to 45,895 UTF-8 bytes, below
the 51,200-byte `TemplateBody` API limit. A read-only AWS `ValidateTemplate`
call accepted it with 15 parameters and reported `CAPABILITY_AUTO_EXPAND`.
The existing Auth `state` release uses both `CAPABILITY_NAMED_IAM` and
`CAPABILITY_AUTO_EXPAND` for its SAM change set. This amendment keeps the
original source under the same CloudFormation stack without a package or
template upload.

An earlier IAM preflight found a separate read blocker in the Auth GitHub
deployment role, `zoolanding-auth-admin-production-deploy`. Its scoped read
policy has since been applied. The 2026-10-02 preflight reconfirmed `allowed`
for all 15 required Auth deploy-role reads and all 97 native action/resource
pairs of the CloudFormation execution role. The protected review passed this
IAM boundary; its failure occurred later at the change-set template comparison.

## Completed prerequisite: scoped deployment-role reads

The protected `auth-owner-read-patch` operation in `zoolandingpage-aws-infra`
was reviewed and executed separately. It modified only the `PolicyDocument`
of `AuthGithubReleasePolicy`, attached to
`zoolanding-auth-admin-production-deploy`, with these scoped reads in account
`765932874577` and region `us-east-1`:

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

Its release passed the workflow and inventory allowlists and applied a single
`Modify` without replacement. It added no write, Cognito mutation, Lambda
invocation, or human-role permissions. The applied policy and all 15/15 exact
read decisions were verified before the Auth owner review. Recheck this proof
before a new review; do not redeploy the completed IAM prerequisite.

## Decision and boundaries

The dedicated manual production workflow and small operator already exist for
this parameter-only transition. Keep the retained release path unchanged.
The workflow runs only from the exact current `main` SHA in the protected
`production` Environment with the existing Auth OIDC deployment role. It has
`review` and `execute` operations and no build, `sam package`, S3 package
write, Cognito mutation, or owner enrollment step.

Review calls `CreateChangeSet` on the existing Auth stack with `TemplateBody`
containing a compact JSON serialization of the **freshly downloaded deployed
Original template**, the current CloudFormation execution role, both
`CAPABILITY_NAMED_IAM` and `CAPABILITY_AUTO_EXPAND`, and the current tags.
The operator must reject a non-dictionary Original, a different transform,
a changed pinned template hash, a body over 51,200 UTF-8 bytes, or a body whose
parsed canonical hash differs from the downloaded Original before the first
write. It must never use a local rebuild, a caller-provided template, or
`UsePreviousTemplate` as a fallback. The request supplies exactly these three
new parameter values:

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
in-progress stack operation. The owner Lambda's exact deployed, versioned S3
package must still exist, be encrypted, and be readable by the deployment role;
its metadata is sealed with the review and rechecked before execution.

## Inventory and approval

After creating the change set, read every page of the native change inventory
and both change-set templates. Require the parsed change-set Original and
Processed templates to match the canonical hashes of the deployed Original
and Processed templates respectively. Report only their hashes and transform
shapes in sanitized diagnostics if this comparison fails, then delete the
change set. Permit only `Add` without replacement for the
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
execution role and 15/15 Auth deploy-role reads; repeat that proof if the
template or either role changes. Check the exact Original body size and run
read-only `ValidateTemplate` against that body before the first Action.
Confirm the identities stack and deployed `AuthGithubReleasePolicy` remain as
reviewed, and simulate all 15 allowed reads. Test the three parameter overrides
against the deployed template locally; translate the SAM template
with the pinned release tooling and compare allowed native resource names.
Exercise offline tests for stale source/baseline, changed or extra parameter,
missing MFA, wrong principal, unrelated native change, replacement, expired
record, and post-execution identity drift. Add a regression for a preview
without the SAM transform, the observed failure class under
`UsePreviousTemplate`. Assert that the new request contains only the exact
Original `TemplateBody`, both capabilities,
and the three overrides. Reject oversize bodies, unknown transforms, or
changed canonical hashes. Replay the complete review path with the freshly
captured AWS stack and template responses up to a barrier immediately before
`CreateChangeSet`; replay both a matching preview and a preview whose Original
lacks the SAM transform to prove cleanup and no execute. Run the relevant Auth
tests and `actionlint` when available. After any code promotion, perform one newly
authorized review; do not reuse the failed review run or its nonexistent digest.

The identities read patch and the first Auth owner operation have already been
promoted through `dev → test → main` with exact selectors and green CI. Promote
this amendment by the same branch sequence without invoking AWS automatically.
Its new `review` and `execute` each require fresh authorization under
`AGENTS.md`.

## Alternatives and acceptance

The existing `state` release is unsuitable for this narrow transition because
it repackages other functions. A private S3 `TemplateURL` would add an object
write and another permission surface. Accepting the processed template as the
new Original could change the stack's template provenance and future release
behavior. Direct CLI execution has no durable source, inventory, and digest
guard. The exact inline Original template keeps the release limited to the
three parameter values and a reviewable resource inventory.

The operation is accepted when its protected review shows only the intended
owner additions, its separately approved execution preserves all existing
resource identities and closed routes, and the operator can be assumed only
by the approved MFA-protected human principal. Creating the client account,
enrolling TOTP, and opening authoring routes remain separate steps.

AWS API reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html
