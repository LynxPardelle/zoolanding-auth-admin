# Isolated QA lifecycle and epoch revocation

Date: 2026-09-08 (Central Time). Implementation and validation are local only;
no commit, publish, AWS mutation or real-account rehearsal is implied.

- Added four server-fixed QA operations inside the existing serialized IAM
  mediator: create, enable, reset and terminal disable. The separate QA client
  uses only the same signed buffered alias. Owner CLI bytes, fixed owner
  purpose, owner singleton, v1 and infrastructure template remain unchanged.
- QA uses a separate transactional reservation with immutable purpose and
  provider-subject binding. Creation/enablement/reset are denied after owner
  binding. Terminal disable retains account/state/content/audits and cannot be
  undone; it removes only QA authority and group membership.
- Reset/disable revoke state/version before provider dependencies. Partial reset
  remains pending/disabled. Partial disable remains retired/disabled. Ambiguous
  enable is quarantined. Retries never silently report incomplete cleanup as
  success and never create another QA identity.
- Added QA-only reservation/version fences before authentication, each challenge
  continuation and atomic enrollment/session commit. Tests cover aliases,
  missing fences, reset/reenablement races, stale cookies, provider failures,
  lost transaction responses, audit failures and real packaged mediator dispatch.
- Extended only the existing exact Lambda source allowlists. V1 and origin
  artifacts exclude QA; no IAM, resource, route, workflow, environment or
  dependency requirement was added. Existing CI discovers the tests and builds
  the same four artifacts.

The new offline regression cases were observed failing before the corresponding
fixes, including the pre-provider revocation and paused-signin races. Full-suite,
SAM, lint, package, dependency and secret checks belong to the final local audit
receipts, not a live rollout claim. Real email selection, password/TOTP ceremony,
post-reset recovery and terminal QA removal remain human rollout gates.

Zero new infrastructure services/resources are declared by this change. New
versions of existing Lambda artifacts are expected during later publication;
reviewed rollback versions must be retained. No cleanup deletion permission or
change to the shared Cognito user-lifecycle service is introduced.
