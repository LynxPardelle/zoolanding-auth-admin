# THN synchronous owner URL and TOTP ceremony

Date: 2026-09-04 (Central Time)

The build-only The Hair Narrative TEST owner operator now uses one buffered
Lambda function URL with `AWS_IAM` authentication instead of direct Lambda
invocation. The operator identity policy and the alias resource policy both
require function-URL invocation, and `lambda:InvokeFunction` is allowed only
when `lambda:InvokedViaFunctionUrl=true`. The named operator cannot use the same
permission for asynchronous or other direct invocation. The URL has no CORS,
API Gateway route, custom domain, DLQ, or destination.

The operator CLI discovers only the exact versioned function URL, validates its
regional Lambda URL shape and auth type, signs one JSON POST with SigV4, and
accepts only a small JSON no-store response. The mediator validates the Function
URL v2 envelope, POST-only root path, empty query, bounded JSON body, and exact
IAM caller before performing an owner operation. Errors and responses remain
sanitized and no request body is logged.

The THN v2 TOTP enrollment ceremony now has a documented narrow browser
exception. Only `POST /auth-v2/session/mfa/setup`, after exact-origin and CSRF
validation, may return the manual setup key. The associated state remains
single-use and expires after five minutes. Responses use no-store,
no-referrer, no-cache, and nosniff headers; the setup key is not retained in the
ephemeral record and must never enter URLs, logs, analytics, screenshots, or
durable notes.

Focused red/green tests covered the function URL resource and policies, direct
invoke denial, signed CLI transport, Function URL event validation, exact IAM
caller validation, and the bounded TOTP response. The full local unit suite
passed after implementation. No AWS, Cognito, DynamoDB, DNS, GitHub, deployment,
account, or writer state changed in this pass.
