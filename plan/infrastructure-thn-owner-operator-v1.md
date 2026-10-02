---
goal: Review and activate only the existing conditional THN production owner operator resources
version: 1.0
date_created: 2026-10-01
last_updated: 2026-10-02
owner: THN production release
status: 'In progress'
tags: [infrastructure, auth, production]
---

# Introduction

![Status: In progress](https://img.shields.io/badge/status-In%20progress-yellow)

Implement the approved parameter-only owner operator release in `zoolanding-auth-admin`.
The approved specification is `docs/superpowers/specs/2026-10-01-thn-production-owner-parameter-review-design.md`.

## 1. Requirements & Constraints

- **REQ-001**: Use the deployed `zoolanding-auth-admin-prod` Original template through `UsePreviousTemplate=true` and change exactly three reviewed parameters.
- **REQ-002**: Review must permit only `Add` of the ten owner operator logical IDs from the current Processed template; any other inventory aborts before execution.
- **REQ-003**: Execution requires a successful review run, exact digest, unchanged source, baseline, IAM proof, and unexpired change set.
- **REQ-004**: Verify existing physical IDs, termination protection, operator trust, URL authorization, and closed Auth routes after execution.
- **SEC-001**: Do not create an owner user, enable public routes, publish articles, or store credentials or MFA material.
- **CON-001**: Keep the existing `deploy-thn-production.yml` release behavior unchanged.
- **CON-002**: Promote source by `dev → test → main` and invoke the new workflow manually only after separate approvals.
- **CON-003**: The production Auth GitHub role currently has `implicitDeny` for `iam:ListMFADevices`, `cognito-idp:ListUsersInGroup`, owner-role reads, `lambda:GetAlias`, `lambda:GetFunctionUrlConfig`, and `cloudformation:ListChangeSets`; do not dispatch the owner review until a separately reviewed IAM patch makes each exact request allowed.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Define exact parameter and inventory guards offline.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Add `tools/thn_production_owner_parameter_release.py` with pure functions to validate deployed Original/Processed templates, the three overrides, ten allowed logical IDs, and the native change inventory. | Yes | 2026-10-02 |
| TASK-002 | Add `tests/test_thn_production_owner_parameter_release.py` covering wrong principal, disabled state, open route, extra parameter, missing/extra owner resource, `Modify`, `Remove`, and replacement. | Yes | 2026-10-02 |

### Implementation Phase 2

- GOAL-002: Implement a retained review and execution without repackaging.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-003 | Add read-only source, branch, stack, human MFA, IAM and baseline preflight; use the current Auth OIDC and CloudFormation execution roles. | Yes | 2026-10-02 |
| TASK-004 | Add `review` that calls `CreateChangeSet` with `UsePreviousTemplate=true`, all non-target parameters as `UsePreviousValue=true`, and `CAPABILITY_NAMED_IAM`; inspect all pages, compare both templates, and seal a sanitized 24-hour digest. | Yes | 2026-10-02 |
| TASK-005 | Add `execute` that verifies the exact review record and current AWS state, executes only its change set, then verifies all old physical IDs and the closed route and owner group. | Yes | 2026-10-02 |
| TASK-006 | Add tests for stale source or baseline, changed IAM, expired digest, unexpected review inventory, rollback, and post-execution identity mismatch. | Yes | 2026-10-02 |

### Implementation Phase 3

- GOAL-003: Integrate the manual workflow and prove it locally before GitHub Actions.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-007 | Add `.github/workflows/deploy-thn-production-owner-operator.yml` with `review` and `execute`, exact `main` SHA, production Environment and OIDC gates, review artifact provenance, and no SAM build/package step. | Yes | 2026-10-02 |
| TASK-008 | Run Auth offline tests, lint the workflow, and replay `review` against current read-only AWS captures to a barrier before `CreateChangeSet`. | | |
| TASK-009 | Review exact local diff and prepare a PR from the `dev` branch; push and merge only after the repository approval gate and CI. | | |
| TASK-010 | After code reaches MAIN, repeat live read-only preflight; seek separate approval for one `review`. Seek another approval for `execute` only after inspecting its inventory and digest. | | |

## 3. Alternatives

- **ALT-001**: The existing `state` release repackages all SAM functions and can change unrelated code coordinates.
- **ALT-002**: Direct CLI execution lacks a source-bound review artifact and repeatable digest gate.

## 4. Dependencies

- **DEP-001**: Current Auth production stack and the exact deployed Original/Processed templates.
- **DEP-002**: Existing Auth GitHub production OIDC role and CloudFormation execution role.
- **DEP-003**: `tools/thn_production_release.py` canonical hashing and retained review helpers.
- **DEP-004**: User approval of the review run and later of its exact inventory digest.
- **DEP-005**: A separately approved policy update in the production deployment-identities stack granting only the exact read operations needed by the Auth GitHub role. Its design was approved; its protected AWS review and execution remain pending.

## 5. Files

- **FILE-001**: `tools/thn_production_owner_parameter_release.py` — new operator.
- **FILE-002**: `tests/test_thn_production_owner_parameter_release.py` — offline regression tests.
- **FILE-003**: `.github/workflows/deploy-thn-production-owner-operator.yml` — manual review and execute.
- **FILE-004**: `docs/superpowers/specs/2026-10-01-thn-production-owner-parameter-review-design.md` — approved design.

## 6. Testing

- **TEST-001**: Offline tests reject every parameter and inventory variant outside the ten owner resources.
- **TEST-002**: Replay of current AWS responses reaches a pre-write barrier without creating a change set.
- **TEST-003**: Workflow lint passes; existing Auth production tests remain green.
- **TEST-004**: Native review, after separate approval, reports only intended `Add` resources and no replacement.
- **TEST-005**: Authorized execution preserves the 37 current physical resources and keeps Auth routes closed.

## 7. Risks & Assumptions

- **RISK-001**: CloudFormation may report a native dependency change not visible in offline translation; reject and diagnose before execution.
- **RISK-002**: Retained resources may remain after a failed stack update; stop and reconcile manually.
- **RISK-003**: A release dispatched before DEP-005 is satisfied will fail before its change set; prove effective IAM decisions with exact resource ARNs and request context first.
- **ASSUMPTION-001**: The deployed Auth template continues to use only `AWS::Serverless-2016-10-31` and already contains ten processed owner resources.

## 8. Related Specifications / Further Reading

- `docs/superpowers/specs/2026-10-01-thn-production-owner-parameter-review-design.md`
- https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html
