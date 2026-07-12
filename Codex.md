# Zoolanding Auth Admin Compatibility Memory

Start with [AGENTS.md](AGENTS.md), then use [README.md](README.md) for the current service contract and [changelog/README.md](changelog/README.md) only for history.

## Durable decisions

- The service owns only the exact `/auth/session/*` and `/auth/admin/*` routes declared in `template.yaml`; Angular keeps `/auth/callback`.
- Tenant, environment, Cognito, group, and approval policy stays in server-only `AUTH_ADMIN_CONFIG_JSON_BASE64`. Browser responses remain sanitized and token-free.
- Sessions use the HttpOnly `__Host-zlp_session` cookie, per-flow CSRF validation, and matching draft/profile context. Admin authorization re-checks current user state and session version.
- Session, user-state, and immutable audit data remain separate, PITR-enabled DynamoDB tables. The Lambda timeout baseline is 30 seconds.
- Feature work starts from `dev` and promotes through `dev -> test -> main`; preserve OIDC, GitHub Environments, and merge-commit guards.

Do not add dated notes here. Put chronology in `changelog/` and update README, code, tests, or workflows when the current contract changes.
