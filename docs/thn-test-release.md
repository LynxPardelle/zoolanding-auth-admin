# Dedicated THN TEST release

This workflow owns only the additive The Hair Narrative Auth Admin TEST boundary.
It does not publish the Journal, onboard its owner, or enable the service-binding
registry. Those remain separate, reviewed rollout steps.

## Preconditions

- Merge the reviewed feature into `dev`, then promote `dev` to `test` with a merge
  commit. Never modify `main` or the production workflow for this release.
- The existing Auth Admin TEST stack must be stable and have actual termination
  protection enabled. The workflow does not create an alternate stack or change
  this protection itself.
- Use the existing `test` Environment role and artifact bucket. A workflow job
  without that Environment cannot read its configuration variables.
- Reconcile all cross-service prerequisites, including the named TEST operator
  role required by the owner mediator resource policy, before provisioning.
- `enable` additionally requires the reviewed, complete
  `THN_V2_TEST_PARAMETERS_JSON` Environment variable. It has schema version 1,
  environment `test`, and exactly the eight THN parameters validated by
  `tools/prepare_thn_test_parameters.py`. Do not put its values in source, logs,
  issue comments, or release artifacts.

## Operations

Run `.github/workflows/deploy-thn-test.yml` at the `test` ref with the reviewed
full commit SHA as `expected_source_sha` and exactly one `operation`:

| Operation | Effect | Preserved |
| --- | --- | --- |
| `provision` | Creates isolated retained state, functions and roles; HTTP and owner URL stay absent | Shared v1 resources and configuration |
| `enable` | Requires previously provisioned state and a complete reviewed descriptor/origin-proof selection; creates the dedicated routes | Retained state, shared v1 resources |
| `disable` | Removes only additive routes, URL permissions, operator-invoke policy and alarms, using the live template without rebuilding code | Functions, execution roles, mediator direct-invoke guard, immutable versions, accounts, tables and logs |

Disable the registry/writer access through its owning operator procedure before
the Auth Admin `disable` operation. This workflow does not write another
service's registry. Re-enable only after the independent origin, registry,
session and access checks pass again. `ProvisionThnAuthAdminV2State` never returns
to false through this workflow.

The initial push to the reviewed candidate branch runs a credential-free
registration job only. After that run, GitHub's API/CLI can dispatch the workflow
against `test`; the validate/deploy jobs reject other refs, events and SHAs.
No production-branch registration commit is required. See
[GitHub workflow dispatch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).

## Delivery and rollback boundary

The validation job builds four allowlisted Lambda payloads without AWS
credentials. The deployment job downloads that run's immutable artifact ID and
checks its exact inventory, manifest digest, source SHA and run coordinates. It
does not check out source. Both ordinary and dedicated deploys share one
concurrency group.

The release composer keeps every non-THN resource and configuration parameter
from the live stack. Shared parameters use CloudFormation `UsePreviousValue`,
including the shared authentication configuration; the workflow never loads or
re-emits its secret. Shared globals must remain compatible. The change-set
review refuses any non-THN resource change, unknown resource type, state
deletion, function/role deletion or replacement. A previous Lambda version can
leave stack management only with the explicit `Retain` policy.

Immediately before execution the stack/template/inventory must still match the
preflight. Afterwards, two observations verify parameters, stable identities,
termination protection and retained-state protections. Failure never triggers
an automatic destructive rollback. Keep access closed and use the recorded
previous artifact/pointers under the cross-service rollback procedure.

`DescribeChangeSet` does not return a `ChangeSetType` field. The runner binds
`UPDATE` in its creation request and verifies the exact resulting ID, name and
stack. See [AWS response contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeChangeSet.html).

## Verification

Run the full unit suite, the four artifact allowlist checks, `cfn-lint` against
`template.yaml`, `actionlint` for the dedicated workflow, and dependency audits
for `requirements.txt`, `requirements-tools.txt` and `requirements-release.txt`.
Live sign-in, MFA, origin isolation and owner acceptance remain rollout gates;
unit tests do not constitute their completion.
