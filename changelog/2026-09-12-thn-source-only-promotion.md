# Exact-source THN TEST validation

Date: 2026-09-12 (Central Time). Source implementation; not a deployment receipt.

Added the optional repository Actions variable
`AUTH_TEST_PROMOTION_SELECTION_JSON` with a closed, exact dev SHA/tree selection.
Absent/empty preserves ordinary legacy TEST delivery; every defined invalid or
stale selection fails before Environment/OIDC/credentials. The existing exact
two-parent/current-dev/whole-tree guard remains unchanged. Only validated
`legacy` mode admits the privileged job.

The selected THN source takes two credential-free build/transport-validation
jobs. A distinct NONDEPLOYABLE schema binds the complete inventory, digest,
source, dev tree, run and attempt; the independent verifier runs from the pinned
source checkout, not transported code. Legacy release and rollback consumers
continue rejecting validation artifacts. No automatic selector cleanup occurs.

Focused tests cover selector failures, real Git/Bash promotion guards, artifact
tamper/provenance/transport, standard-library-only CLI operation and actual
legacy metadata-consumer rejection. Full tests and package/workflow checks are
required before publication; cloud CI, variable readback and the eventual TEST
promotion need their own receipts.

V1 handlers/dependencies, template/IAM, production, legacy rollback and the
private lifecycle are unchanged. See the [current release contract](../docs/thn-test-release.md#exact-source-test-promotion).
