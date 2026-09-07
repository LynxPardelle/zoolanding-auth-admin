# THN validation-only candidate

Date: 2026-09-07 (Central Time)

- Add an isolated GitHub validation workflow triggered only by `codex/thn-task029-auth-admin`.
- The job has read-only repository permissions, no cloud credentials or environment approval, and no deployment or promotion step.
- Run the owning repository's tests and build checks; retain an explicitly non-deployable candidate package and source/run/digest receipt for 30 days.
- Existing deployment triggers, activation defaults and other drafts are unchanged. The artifact is QA evidence, not a legacy recovery migration or a deployment authorization.

Validation: parsed workflow boundary checks and Actionlint. Remote test results belong to the corresponding GitHub run, not this source document.

Remote linting exposed a stale bundled CloudFormation schema. The isolated QA
workflow now uses cfn-lint 1.56.0 in its own environment, with no ignored rules;
SAM remains the package builder. The current validator also caught the bare
YAML `ON` scalar in the dedicated Cognito pool. Quoting `'ON'` preserves the
intended mandatory TOTP setting as the string required by CloudFormation.
The template regression was corrected before the one-line template fix.
No existing identity policy, resource policy, route or activation flag changed.
