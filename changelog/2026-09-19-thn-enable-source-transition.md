# 2026-09-19 — Validate THN enable source transition

The first TEST enable attempt after the package-preservation correction stopped
before a change set because the deployed packages were provisioned from the
previous TEST commit. The correction itself necessarily changed the workflow
source SHA, while GitHub comparison confirmed only release tooling, tests and
documentation had changed; no Lambda runtime source changed.

The credential-free validation job now requires the provisioned commit to be
an ancestor and restricts every intervening changed path to an exact allowlist.
The release tool separately requires the three deployed package references to
carry that provisioned commit, the candidate references to carry the current
reviewed TEST commit, and all function properties to remain identical. This
is an activation-only transition. It does not relax the replacement guard,
rerun provisioning, change shared v1 or claim successful deployment.
