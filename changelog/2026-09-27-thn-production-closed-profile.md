# THN production profile and source promotion preparation

This additive slice retains the exact TEST binding and adds a closed logical
production profile. SAM prod is explicitly mapped to descriptor production;
production host, table/key and cookie scope cannot be supplied by the browser.
Production rejects QA accounts and qa-only registry writer state. Shared v1
handlers are unchanged. The TEST owner CLI adds one exact fail-closed profile
guard. Its existing lifecycle bytes and the TEST template remain frozen after
that single guard is accounted for; production cannot redirect the TEST pool
to production current-user state.

The source-only main promotion selector pins source SHA/tree, target base and
native merge tree. Missing/stale/duplicate selections fail before credentials.
The production push job cannot deploy during this coordinated source promotion.

Offline production SAM projection preserves all v1 resources, includes retained
THN state with toggles disabled, excludes the TEST owner/QA mediator, and blocks
route activation until a separately reviewed production owner operator is proved.
The projection is a candidate, not evidence of effective IAM permissions or an
approved change set. No AWS or GitHub operation is performed by these tools.

Pending: dedicated production owner lifecycle, review/execution workflow,
permission simulation, live baseline/native projection comparison and separately
approved deployment inventory. No client or QA data is migrated.

Production release supports retained native previews, exact digest execution, sealed package and prior-byte recovery, and independent general v1 review. Fresh source authority is checked before credentials and immediately before native changes. IAM simulations evaluate actual action/resource context rather than unrelated whole-policy context. Production operator grants remain closed behind exact human principal, MFA and separately reviewed native inventory; no TEST QA data or credentials are copied.

The protected source promotion now checks the parsed native merge commit
against GITHUB_SHA. This resolves the actual ShellCheck SC2034 unused-variable
failure and explicitly binds the head identity. Actionlint 1.7.12 with the CI
ShellCheck 0.9.0 validates every tracked workflow without suppressing checks.
