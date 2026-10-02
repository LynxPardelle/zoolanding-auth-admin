---
goal: Preserve the deployed SAM template in the production owner parameter review
version: 1.0
date_created: 2026-10-02
last_updated: 2026-10-02
owner: Zoolanding Auth Admin
status: 'In progress'
tags: [infrastructure, bug, production, thn]
---

# Introduction

![Status: In progress](https://img.shields.io/badge/status-In%20progress-yellow)

Correct the owner review contract after run 37071052433 rejected the change-set template with `production_owner_transform_invalid`. The code change must preserve the deployed Original and Processed template hashes and limit the release to the ten owner resource additions.

## 1. Requirements & Constraints

- **REQ-001**: `owner_change_set_request` must serialize the freshly captured deployed Original template as a compact JSON `TemplateBody` and omit `UsePreviousTemplate` and `TemplateURL`.
- **REQ-002**: Require the serialized body to be at most 51,200 UTF-8 bytes and to parse back to the same canonical template hash.
- **REQ-003**: Request `CAPABILITY_NAMED_IAM` and `CAPABILITY_AUTO_EXPAND`; keep the existing stack ARN, execution role, tags, and exactly three parameter overrides.
- **REQ-004**: Require both change-set template hashes and the exact ten `Add` inventory entries before emitting a review digest.
- **SEC-001**: Abort and delete a newly created change set on any template, parameter, identity, or inventory mismatch; never execute it during review.
- **CON-001**: Do not rebuild or upload SAM packages, copy TEST users, open Auth routes, or publish content.
- **CON-002**: No GitHub push, merge, or AWS review until the separate authorizations required by `AGENTS.md` and the approved design.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Reproduce the failed contract and implement the exact inline template request.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | In `tests/test_thn_production_owner_parameter_release.py`, make the request test require `TemplateBody` with the deployed Original hash, both capabilities, and no `UsePreviousTemplate`; confirm it fails before editing the operator. | Yes | 2026-10-02 |
| TASK-002 | In `tools/thn_production_owner_parameter_release.py::owner_change_set_request`, serialize `current['original']`, enforce the byte limit and hash round-trip, and return the revised request without changing its other fields. | Yes | 2026-10-02 |
| TASK-003 | Add negative tests for an oversized body, unknown transform, changed template hash, and a preview whose Original lacks the SAM transform; require cleanup and no digest on mismatch. | Yes | 2026-10-02 |

### Implementation Phase 2

- GOAL-002: Verify the guarded review path against the current production baseline before a GitHub Action.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | Run the owner release unit tests and full Auth offline suite, `git diff --check`, dependency audits, SAM validation, and `actionlint` where installed; report unavailable tools. | Yes | 2026-10-02 |
| TASK-005 | Replay the review with captured AWS stack and template responses up to the barrier immediately before `CreateChangeSet`; verify the request body is the exact Original and the proposed overrides are the three approved values. | Yes | 2026-10-02 |
| TASK-006 | Refresh AWS CLI read-only checks for stack, template hashes, package version, no competing change set, Cognito group, MFA, and 15 deploy-role plus 97 native permission decisions. | Yes | 2026-10-02 |

### Implementation Phase 3

- GOAL-003: Promote reviewed code through guarded branches and request a new protected review.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-007 | Under separate approval, commit and open a draft PR to `dev`; inspect the exact diff and wait for mandatory CI before merging. | | |
| TASK-008 | Under separate approval, promote `dev → test → main` with exact selectors; verify each automatic AWS deploy job is skipped. | | |
| TASK-009 | Under separate approval, execute one new owner `operation=review` from the promoted MAIN; present its complete inventory and digest before any `execute`. | | |

## 3. Alternatives

- **ALT-001**: Upload the Original template to S3 and use `TemplateURL`; rejected because it adds a write and permission surface.
- **ALT-002**: Accept the processed template as the new Original; rejected because it changes stack template provenance and could affect later releases.
- **ALT-003**: Repeat `UsePreviousTemplate`; rejected by the observed transform mismatch in run 37071052433.

## 4. Dependencies

- **DEP-001**: Deployed Auth stack `zoolanding-auth-admin-prod` in account `765932874577`, region `us-east-1`, with termination protection and 37 existing resources.
- **DEP-002**: Python 3.13, declared Auth release dependencies, and the GitHub Actions checks already used by this repository.
- **DEP-003**: Separate user approvals for remote writes and each protected AWS review or execute.

## 5. Files

- **FILE-001**: `tools/thn_production_owner_parameter_release.py` — change-set request construction and bounds.
- **FILE-002**: `tests/test_thn_production_owner_parameter_release.py` — regression and negative tests.
- **FILE-003**: `changelog/` entry for the failed review and fix, if required by repository history conventions.

## 6. Testing

- **TEST-001**: The request test fails with the old `UsePreviousTemplate` implementation and passes with the exact deployed Original `TemplateBody`.
- **TEST-002**: The body is 45,895 UTF-8 bytes for the captured production Original, below the 51,200-byte limit, and its canonical hash equals the deployed Original hash.
- **TEST-003**: Negative tests reject oversized or changed bodies, wrong transform, unrelated inventory, and a preview missing the SAM transform.
- **TEST-004**: Full offline Auth suite and local replay pass before the next Action.

## 7. Risks & Assumptions

- **RISK-001**: AWS SAM processing of the explicit Original may produce a changed Processed template. The review guard must detect this, delete its change set, and avoid execution.
- **RISK-002**: The template could grow beyond 51,200 bytes. The operator must fail before `CreateChangeSet` rather than upload a fallback template.
- **RISK-003**: IAM simulation reports `implicitDeny` for `CreateChangeSet` on the service-owned SAM transform ARN even for an unconditional custom Allow. Exact transform grants are present on both the GitHub deploy and CloudFormation execution roles, the deploy role is allowed on the exact stack ARN, and an earlier protected Auth `state` review succeeded with the same roles and SAM transform. The deploy role has no `cloudformation:TemplateUrl` condition, so an inline body is within its policy. Treat the transform simulator result as inconclusive; the next protected review must stop and diagnose any actual authorization error before another run.
- **ASSUMPTION-001**: The deployed Original and Processed hashes remain equal to the pinned baseline; refresh AWS evidence before review.

## 8. Related Specifications / Further Reading

- [Approved owner parameter review design](../docs/superpowers/specs/2026-10-01-thn-production-owner-parameter-review-design.md)
- [Failed owner review 37071052433](https://github.com/LynxPardelle/zoolanding-auth-admin/actions/runs/37071052433)
- [AWS CreateChangeSet API](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html)
