# Offline CI validation

Date: 2026-09-07 (Central Time)

The new `Offline tests (no AWS)` workflow runs the complete Python unit suite on a standard Ubuntu runner. Dependencies install first; the test process and its children then run inside a separate network namespace with an empty inherited environment, isolated home directory and disabled AWS credential files. The workflow has read-only repository permission, no environment or OIDC permission, a 15-minute timeout and cancellation of superseded validation runs. It uploads no artifacts and creates no cache.

Pull requests validate automatically once this workflow is present in their merge tree. The initial `codex/thn-cicd-offline` branch also validates on push. Manual dispatch becomes available after the workflow reaches the default branch. Existing deployment and rollback workflows are unchanged; this check does not prove live AWS permissions, service integration or recovery.

Local verification: the complete suite passed with a Python network audit guard and no network attempts. The Linux network namespace is additionally verified by the GitHub run linked from the pull request. GitHub runner verification is a separate check; do not infer it from the local Windows result.

