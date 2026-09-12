# Dedicated THN TEST release

This workflow owns only the additive The Hair Narrative Auth Admin TEST boundary.
It does not publish the Journal, onboard its owner, or enable the service-binding
registry. Those remain separate, reviewed rollout steps.

## Preconditions

- Merge the reviewed feature into `dev`, configure the exact-source selection
  below, then promote that reviewed `dev` to `test` with a merge commit. Never
  modify `main` or the production workflow for this release.
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

## Exact-source TEST promotion

Ordinary Auth TEST deployment rebuilds shared v1 and supplies its deployment
parameters. It is not the private lifecycle's v1-preserving composer. To promote
THN source without that ordinary deployment, a trusted repository release
operator must explicitly set **repository Actions variable**
`AUTH_TEST_PROMOTION_SELECTION_JSON` after the reviewed source reaches `dev`.
Do not use the `test` Environment variable namespace: selection must happen
before an Environment is selected.

The closed JSON object has exactly four fields:

| Field | Required value |
| --- | --- |
| `schemaVersion` | Integer `1`, not a boolean |
| `mode` | `thn-source-only` |
| `devSha` | Exact reviewed current `dev` commit, 40 lowercase hexadecimal characters |
| `devTree` | That commit's exact whole tree, 40 lowercase hexadecimal characters |

The selector is non-secret release intent, not authorization to deploy. It must
contain no private configuration or resource identifiers. Labels, branch names,
partial hashes and caller-provided mode overrides are not selectors. Read back
the exact variable and independently verify both Git identities before the
normal `dev` to `test` merge. No forced update, squash or rebase promotion is
allowed: the existing guard requires exactly two parents, the event's previous
TEST commit first, fetched current `dev` second, and a whole tree equal to `dev`.

`tools/classify_test_promotion.py` reads the repository variable once in the
credential-free `validate` job, after that guard and before build. Absent or
empty text means `legacy`; whitespace is defined invalid text. JSON duplicates,
unknown fields/modes, wrong types, malformed JSON, input over 4,096 UTF-8 bytes,
and stale/mismatched identities fail closed with fixed diagnostics. A failed,
empty or unknown classifier output cannot start privileged work. Later jobs
consume only the validated mode output, never the mutable variable again.

- `legacy`: unchanged release artifact, Environment `test`, parameter setup,
  ordinary v2 guard and reviewed change-set workflow.
- `thn-source-only`: `validate` builds and uploads only the validation artifact;
  `verify-thn-validation` downloads its immutable artifact ID and verifies it
  using tools checked out at the exact run source. Neither job selects an
  Environment, requests OIDC, reads secrets, configures AWS credentials,
  packages a SAM deployment, executes a change set or enables THN.

The validation artifact name contains `test-validation`. Transport has exactly
`build/` and `validation-manifest.json`. The build contains four allowlisted
Lambda directories, `template.yaml` and `validation-metadata.json`, but no
release tools or legacy metadata. Schema `zoolanding-test-validation/v1` declares
`purpose: validation-only`, `deployable: false` and the selected mode, exact
source/dev/tree/run/attempt. Its complete per-file inventory and manifest SHA-256
are checked against the build job's digest; project source bytes must also match
the trusted source checkout. Unexpected files, links, foreign host binaries,
replayed attempts and provenance drift are rejected. The verifier needs only
the Python standard library and never executes code from the artifact. This is
**NONDEPLOYABLE** evidence: strict legacy deploy/rollback consumers reject its
schema (and missing release manifest) before AWS credential configuration.

The variable is never automatically cleared. A later `dev` source deliberately
blocks until an operator reviews a replacement exact selection or its removal.
Removal restores ordinary shared-v1 deployment; it is a separate release
decision, not cleanup. This opt-in mode does not change other drafts' default
legacy flow, production, private lifecycle behavior, IAM or runtime packages.
Successful source validation does not prove private activation or live QA.
Dispatch the dedicated lifecycle only after its separate approved gates pass.

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

## QA rehearsal and terminal closure

The existing four-target artifact build includes the server-fixed QA dispatcher
and [QA operator client](../tools/provision_thn_qa.py) only in the owner-mediator
payload, and the read-only epoch contract in the v2 session payload. Source
allowlist checks reject QA operator code in v1, v2 session or origin-authorizer
artifacts. Current CI uses test discovery and those exact allowlists; workflows,
permissions, environments and infrastructure declarations are unchanged by QA.

QA provisioning is not a deployment-workflow operation. Use only the same
reviewed human IAM role and buffered versioned mediator alias, before owner
onboarding, with `qa-create`, `qa-enable`, `qa-reset` or `qa-disable`. The client
prompts for private values and accepts no purpose/scope/subject selector. The
owner CLI and its sole `client-owner` reservation remain unchanged.

Complete recovery/reset and fresh human MFA rehearsal before terminal removal.
`qa-reset` revokes the current epoch first and stays disabled; provider failure
leaves reset pending, so only another reset can complete it before enablement.
`qa-disable` first retires the exact reserved identity and revokes its epoch,
then disables provider access, globally signs out and removes only that QA
identity's group membership. Retry terminal disable until provider cleanup is
confirmed; it never reactivates QA or deletes its account, state, content or
audit. Old cookies and challenges must be rejected. A retired QA reservation
or an existing owner reservation permanently denies QA create/enable/reset.

No extra AWS service, resource declaration, permission, route, domain, pool or
function is introduced for the rehearsal or its cleanup. Immutable versions of
the existing Lambda artifacts are normal release lifecycle objects, not a new
service; preserve the reviewed rollback versions. Do not claim final live QA
cleanup from local tests: it requires the approved account and human ceremony,
followed by terminal-disable evidence without private values.
