# Auth Admin Profile Configuration

Deployments pass a base64-encoded JSON config through `AuthAdminConfigJsonBase64`. The value is server-only; repository examples use placeholders.

```json
{
  "version": 1,
  "profiles": [
    {
      "enabled": true,
      "environment": "test",
      "domain": "example.com",
      "authProfileId": "staff",
      "provider": "cognito",
      "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE",
      "userPoolId": "us-east-1_EXAMPLE",
      "clientId": "public-client-id",
      "audiences": ["public-client-id"],
      "tenantId": "example-tenant",
      "tenantClaim": "custom:tenant_id",
      "environmentClaim": "custom:zoolanding_env",
      "environmentClaimMode": "single",
      "groupClaim": "cognito:groups",
      "allowedGroups": ["example-client", "example-admin"],
      "adminGroups": ["example-admin"],
      "manageableGroups": ["example-client", "example-admin"],
      "defaultUserStatus": "pending",
      "adminGroupsAutoApproved": true,
      "customAuth": {
        "signin": { "enabled": true }
      },
      "mfa": {
        "mode": "optional",
        "totp": {
          "enabled": true,
          "issuer": "Example",
          "accountLabelTemplate": "{email}",
          "friendlyDeviceName": "Example access"
        }
      },
      "session": {
        "challengeRespondPath": "/auth/session/challenge/respond",
        "mfaSetupPath": "/auth/session/mfa/setup",
        "mfaVerifyPath": "/auth/session/mfa/verify",
        "mfaEnrollStartPath": "/auth/session/mfa/enroll/start",
        "mfaEnrollVerifyPath": "/auth/session/mfa/enroll/verify",
        "mfaDisablePath": "/auth/session/mfa/disable",
        "challengeCsrfCookieName": "zlp_challenge_csrf",
        "mfaEnrollCsrfCookieName": "zlp_mfa_enroll_csrf"
      },
      "admin": {
        "usersPath": "/auth/admin/users",
        "approveUserPathTemplate": "/auth/admin/users/{subject}/approve",
        "groupsPathTemplate": "/auth/admin/users/{subject}/groups",
        "suspendUserPathTemplate": "/auth/admin/users/{subject}/suspend",
        "reactivateUserPathTemplate": "/auth/admin/users/{subject}/reactivate",
        "resetUserMfaPathTemplate": "/auth/admin/users/{subject}/mfa/reset"
      }
    }
  ]
}
```

## Rules

- `adminGroups` and `manageableGroups` must be subsets of `allowedGroups`.
- `environmentClaim`, when present, must be a Cognito custom claim such as `custom:zoolanding_env`.
- `environmentClaimMode` defaults to strict `single`. Use `list` only when a server-managed claim such as `prod,test` should authorize the same verified user in multiple stack environments.
- Config rejects secret-like keys and common secret-looking values.
- The deployed stack environment must match the selected profile `environment`.
- Stack-created DynamoDB tables are default storage. A per-profile `tables` block may point a profile to draft-specific tables only when that isolation is explicitly configured server-side.
- `mfa.mode` may be `off`, `optional`, or `required`; `optional` and `required` require TOTP to be enabled in profile policy and Cognito.
- `mfa.totp.issuer`, `accountLabelTemplate`, and `friendlyDeviceName` are optional authenticator display fields. Template placeholders are limited to `{domain}`, `{authProfileId}`, `{tenantId}`, `{username}`, and `{email}`.
- TOTP setup material is sensitive. Return it only for explicit enrollment; never put it in URLs, logs, analytics, or durable notes.
- `/auth/session/mfa/disable` is self-service only after password plus current TOTP reauthentication. Lost-device recovery remains an admin/support path.
- `/auth/admin/users/{subject}/mfa/reset` disables the target software-token preference, bumps session version, and audits the action without exposing or deleting a TOTP secret in browser responses.
