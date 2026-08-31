# 2026-08-31 — THN registry v2 consumer build

## Scope

- Added an additive, dormant Auth Admin v2 consumer for the single
  Content-Hub-owned The Hair Narrative service-binding registry row.
- Kept every v1 route, handler, session, cookie, MFA, and existing data-store
  behavior unchanged. TASK-015 remains intentionally unimplemented.
- Added a TEST-only identity policy that permits only strongly scoped
  `dynamodb:GetItem`; no registry write, query, scan, batch, or transaction
  permission was added.

## Fail-closed contract

The consumer uses one code-owned table/key and a strongly consistent read. It
validates the closed descriptor coordinates, positive expected registry
revision, full ownership tuple, reservation owner, activation state, writer
mode/epoch, cookie/auth binding, and exact trusted AWS resource coordinates.
Missing, duplicate-shaped, inactive, stale, malformed, mismatched, or provider
error responses return the same sanitized unavailable error. No local registry
copy or cache is persisted.

## Verification

- TDD RED: the focused consumer test initially failed because the v2 module did
  not exist.
- Focused consumer suite: 7 tests passed.
- Consumer plus repository-contract suite: 11 tests passed.
- Full offline suite: 56 tests passed.
- `sam validate --lint`: template valid.
- Codex Security diff scan: no reportable findings; coverage remained partial
  only because the Content Hub table resource policy is a separate
  cross-repository integration prerequisite.
- `pip-audit` was unavailable on this workstation and was not counted as a
  passing check.

No push, deployment, AWS mutation, Cognito change, or session/MFA change was
performed.
