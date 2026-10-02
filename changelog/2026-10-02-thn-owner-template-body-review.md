# 2026-10-02 — Production owner review template source

Protected owner review #37071052433 created a change set but rejected its
template views with `production_owner_transform_invalid`; the guard deleted the
change set without changing the Auth stack. The request used
`UsePreviousTemplate=true`, and the failed change-set template bodies were not
retained. Reusing the processed template is a likely explanation, not a
confirmed AWS response.

The owner review now submits a compact JSON `TemplateBody` from the freshly
downloaded, hash-pinned deployed Original template and acknowledges both named
IAM and SAM expansion. It rejects a changed, invalid, or oversized body before
`CreateChangeSet`. The preview still requires the same deployed Original and
Processed hashes and exactly ten owner resource additions; mismatch deletes the
temporary change set. The previously deployed routes and accounts are untouched.

Offline verification passed 469 Auth tests, `actionlint`, `sam validate`, and
both dependency audits. The refreshed production Original is 45,895 bytes,
matches the pinned hash, and translates locally to the exact deployed
Processed hash and generated owner version. AWS read-only checks found the stack
stable and protected with 37 resources, no competing change set, one human MFA
device, an empty `journal-owner` group, and the exact retained package. IAM
simulations passed 15 deploy-role reads and 97 native provider decisions. The
deploy role also simulates `allowed` for `CreateChangeSet` on the exact stack
ARN and `iam:PassRole` on the exact execution role with the CloudFormation
service context; its live policies have no `cloudformation:TemplateUrl`
condition. The IAM simulator gave an inconclusive `implicitDeny` for the AWS-owned SAM
transform ARN even with an unconditional custom policy; exact grants are
attached to both the deploy and execution roles, and an earlier protected Auth
state review successfully created a SAM change set using those same roles.

No protected AWS review or AWS write was initiated for this correction. A newly
authorized protected review is required after source promotion; execution of
any resulting digest needs a separate approval.
