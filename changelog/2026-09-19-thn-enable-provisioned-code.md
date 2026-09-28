# 2026-09-19 — Preserve provisioned THN code during enable

The dedicated TEST `enable` operation reuses the three THN function package
references installed by `provision` when no function property changed. The
build and artifact allowlist checks still run. The subsequent source-transition
gate documents and verifies the exact earlier provisioning commit and permits
only release-tooling and documentation changes before activation. A changed
runtime source, function set, package provenance or property blocks the release.

This addresses a change-set rejection caused by a refreshed dependency package
that unnecessarily republished the owner mediator alias and made CloudFormation
mark its protective resource policy as a possible replacement. The replacement
guard remains unchanged. Offline tests cover source and property drift; an
unexecuted diagnostic TEST change set showed no possible replacement. This entry
records the code correction, not a deployed activation.
