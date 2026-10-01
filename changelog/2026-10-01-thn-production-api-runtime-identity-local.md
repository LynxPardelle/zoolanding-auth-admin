# Dedicated THN production API runtime identity: local source repair

The identity generator now emits the exact production API Lambda function, log group, external runtime role, and `iam:PassRole` proof. The API slice was overlaid on the existing manifest while preserving non-API resources, proof rows, and policy revisions. This is source-only local work; the role has not been created in AWS.

The full Auth unit suite passed 446 tests. The runtime role must be reviewed and applied through the protected Infra identity workflow before the API service is deployed.
