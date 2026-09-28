# 2026-08-31 — THN v2 consumer isolated from shared v1 role

## Scope

- Removed the THN service-binding registry read policy from the shared Auth
  Admin v1 Lambda role.
- Kept the additive `service_binding_registry_consumer_v2.py` module and its
  fail-closed contract tests dormant for a future dedicated v2 identity.
- Kept all existing v1 routes, handlers, session behavior, workflows, and
  production topology unchanged.

## Verification

- TDD RED reproduced the boundary regression: the repository contract failed
  while the shared role still referenced the THN registry policy.
- Focused repository and registry consumer suite: 10 tests passed.
- Full offline suite: 58 tests passed.
- `sam validate --lint`: template valid.
- `git diff --check`: passed.
- `pip-audit` and `actionlint` were unavailable on this workstation and were
  not counted as passing checks.

No push, deployment, AWS mutation, Cognito change, v1 route change, or
production change was performed.
