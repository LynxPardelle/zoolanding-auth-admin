# Production permission review corrections - 2026-09-28

## Cause and change

- Actual read-only IAM CLI controls reproduced `implicitDeny` for selected mixed-case API Gateway, SNS and Logs action spellings, while the same action in lowercase was allowed with the same principal, resource and context. IAM action names are case insensitive. Normalize only simulator input; preserve reviewed requests, IAM policy documents, resource ARNs and conditions.
- Require complete per-action resource coverage. AWS can return one action summary with nested resource results. Missing, duplicate, denied, truncated or context-incomplete results still stop review.
- Project CloudWatch LogGroup permissions from the live provider onto the supported basic log group. Preserve reads, creation, deletion/rollback, retention and tags; omit mutations for absent KMS, data-protection, delivery, field-index, resource-policy, bearer-token and deletion-protection features.
- Reject unsupported LogGroup features in either previous or candidate properties. Explicitly clearing an old feature cannot conceal its removal requirements.

## Evidence and verification

- Live `AWS::Logs::LogGroup` default provider handler permissions were captured in us-east-1 on 2026-09-28; the account-free permissions fixture is included.
- Regression tests failed before the corrections and passed afterwards. They cover Add/Modify/Remove projections, unsupported old/new features, unchanged request context/resources and complete multi-resource simulation coverage, including explicit denies and missing context.
- Actual production identities execution completed; a subsequent read-only comparison matched all 30 approved resources, eight new role policy/trust sets, five preserved existing roles and the private versioned bucket.
- The full local repository suite passed on Windows Python 3.12.14 with declared dependencies installed in a fresh isolated environment. Mandatory GitHub CI on Python 3.13 remains required before integration.

## Scope

Only deployment review tooling, tests and this evidence note change. No IAM permission expansion, Lambda payload change, AWS service execution, production owner enrollment or article publication is included.

Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html
