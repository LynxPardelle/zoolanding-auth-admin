# THN TEST named-stage auth route repair

Date: 2026-09-26 (Central Time).

- A real anonymous request to `GET /auth-v2/session/me` returned 403. The
  diagnostic origin authorizer logged the sanitized denial reason `route`.
  CloudFront forwards the six dedicated session routes to the API's named
  `/test` stage, while API Gateway route keys omit that stage prefix.
- The origin authorizer now removes only a leading `/test/` from the HTTP path
  before its exact six-route, route-key, and route-ARN checks. It accepts the
  raw path with or without the stage prefix, while retaining the `test` stage,
  origin proof, forwarded host, origin, and viewer IP checks.
- The v2 session handler applies the same named-stage normalization before
  dispatch. Without it, a request admitted by the authorizer could return 404.
- Unit tests cover the stage-prefixed event at both boundaries; the full
  offline suite passed 380 tests. The prepared TEST packages replace only the
  respective Python source file in each currently active Lambda ZIP; package
  entry comparison confirmed all other files are byte-identical.
- Any direct Lambda code update is temporary CloudFormation code drift. A
  subsequent stack update must use reviewed source and an exact change-set
  inventory or it may restore the previous code. The previous active ZIPs are
  retained as rollback inputs.
