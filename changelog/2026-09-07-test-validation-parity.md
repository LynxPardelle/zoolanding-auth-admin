# TEST template validation parity

Date: 2026-09-07 (Central Time).

The unprivileged validation job in `deploy-test.yml` now uses the same isolated,
pinned `cfn-lint` 1.56.0 schema check already proven by the THN candidate workflow.
It replaces basic `sam validate` before the unchanged SAM build. No rules are
ignored and the failure threshold is not relaxed. This does not change runtime
dependencies, the credential-bearing job, promotion guards, TEST activation
parameters, production workflows, or any AWS resource.

A regression failed before the change and then passed. Three complete local
rounds passed the service tests, template schema validation, Actionlint, diff
checks and parsed comparisons proving the credential-bearing jobs and release
boundaries unchanged. The new regression uses only Python's standard library.
No deployment or account operation was performed.
