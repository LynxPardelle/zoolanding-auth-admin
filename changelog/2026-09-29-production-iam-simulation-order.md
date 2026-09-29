# Stable production IAM simulation evidence

The Auth production state execution run 36604949768 stopped before CloudFormation execution with `production_permissions_changed`. The preceding review run 36604426384 remains an unexecuted native change set. Read-only reproduction showed that `SimulatePrincipalPolicy` returned the same allowed decisions, resources, and matching policies while changing the order of `MatchedStatements` inside `ResourceSpecificResults`. The raw response order had been included in `permissionSha256`.

Sort provider evidence arrays before sealing or comparing the permission fingerprint. Preserve each action, resource, context, decision, missing-context value, matched policy identifier, and statement position. A denied decision or changed policy still changes the fingerprint. The same release guard is used by Auth Admin, API Proxy, Content Hub, and Image Upload, so each service carries this correction.

The earlier Auth review digest is tied to the old source and fingerprint algorithm. After this code is promoted, create a new protected review and inspect its inventory before any execution. Source promotion alone does not deploy AWS.
