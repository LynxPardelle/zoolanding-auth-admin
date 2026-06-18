# Zoolanding Auth Admin Codex Memory

This repository owns the generic serverless auth-admin BFF for Zoolanding draft authentication.

## Durable Decisions

- The Lambda is generic across drafts. It resolves all tenant, user-pool, group, approval, and environment policy from server-only `AUTH_ADMIN_CONFIG_JSON_BASE64`.
- The browser receives only sanitized account/session metadata. No JWT, ID token, access token, refresh token, Cognito client secret, or upstream credential is returned to the browser.
- The current BFF session path is custom sign-in only. Cognito Managed Login / Hosted UI remains compatible for drafts that choose it, but it needs a future server-side callback/token-exchange endpoint before it can mint the same HttpOnly BFF session.
- Authenticated browser sessions use `__Host-zlp_session` as an HttpOnly, Secure, SameSite=Lax cookie plus a readable `zlp_csrf` cookie that must match `X-ZLP-CSRF` on mutating requests.
- Session/admin requests must include `X-ZLP-Domain` and `X-ZLP-Auth-Profile-Id`; the Lambda resolves the server-only profile from those headers and rejects cookies used against a different draft/profile context.
- `/mi-cuenta` uses `GET /auth/session/me` and is allowed for any authenticated user, including users pending admin approval.
- `/admin/*` workflows require an approved user with a configured admin group, and the handler re-checks that policy server-side on every admin request.
- Cognito group updates use Cognito as the source of truth for current groups, then write the resulting allowed roles back to user state.
- New self-registered users should remain in the profile default status, usually `pending`. Users in configured admin groups may be auto-approved because Cognito group assignment is already an administrator-controlled operation.
- DynamoDB state is split by purpose: private sessions, durable user state, and immutable audit events. The default deployment creates stack-local tables; future per-draft stacks or per-profile table names can provide stronger draft isolation.
- Stack-owned auth-admin DynamoDB session, user-state, and audit tables must have point-in-time recovery enabled in every environment (`dev`, `test`, and `prod`). This is a no-interruption CloudFormation update and protects account/session/admin audit state from accidental writes or deletes.
- Keep the Lambda timeout above cold-start auth dependency latency. Production sign-in hit the old 15-second limit on 2026-06-17 CT during a Cognito-backed `/auth/session/signin`; the SAM baseline is now 30 seconds so cold Cognito/JWKS/Dynamo paths can fail with controlled JSON instead of platform timeout.
- 2026-06-18 00:21 CT: Cognito MFA challenge support is generic and profile-driven. `SOFTWARE_TOKEN_MFA` and `MFA_SETUP` store raw Cognito `Session` values server-side as challenge records, set short-lived `__Host-zlp_challenge` and `zlp_challenge_csrf` cookies, and require `X-ZLP-CSRF` before `/auth/session/challenge/respond`, `/auth/session/mfa/setup`, or `/auth/session/mfa/verify` call Cognito. Successful challenge completion clears challenge cookies and creates the normal HttpOnly BFF session.
- 2026-06-18 00:21 CT: The auth-admin IAM policy must include the Cognito challenge actions `cognito-idp:RespondToAuthChallenge`, `cognito-idp:AssociateSoftwareToken`, and `cognito-idp:VerifySoftwareToken`, scoped to `COGNITO_USER_POOL_ARNS`. Expected Cognito challenge failures should map to controlled 401 responses, not platform 500s.
- Branch flow follows other Zoolanding serverless repos: `dev -> test -> main`, with OIDC deploys from GitHub Environments and branch-protection checks.
- GitHub native branch protection for this private repo was blocked by the account plan on 2026-06-17 CT: the API returned `403` with `Upgrade to GitHub Pro or make this repository public to enable this feature.` Until the plan supports private branch protection, CI/deploy workflow guards enforce the promotion graph and deploy branches require merge commits from the expected upstream branch.
