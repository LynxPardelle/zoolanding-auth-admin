# Zoolanding Auth Admin Agent Guide

<!-- zoolanding-hub-routing:start -->
## Zoolanding Knowledge Router

Read only the row needed for the current task, then inspect the local executable configuration or workflow that owns the behavior.

| Task | Read |
| --- | --- |
| Auth profile contract | [docs/api-driven-config/17-auth-profile-registry.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/17-auth-profile-registry.md) |
| Protected feature contract | [docs/api-driven-config/19-protected-feature-contract.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/19-protected-feature-contract.md) |
| Draft auth audit | [docs/api-driven-config/18-draft-auth-audit-matrix.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/18-draft-auth-audit-matrix.md) |
| Fleet ownership | [docs/repository-map.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/repository-map.md) |

Critical repository-specific safety, deployment, and rollback rules remain local.
<!-- zoolanding-hub-routing:end -->

Use this file as the repository entrypoint for agents and contributors.

## Read order

1. Read [README.md](README.md) for the current service contract, routes, security model, local checks, and deployment topology.
2. Read [lambda_function.py](lambda_function.py), [template.yaml](template.yaml), and only the relevant tests under [tests/](tests/) before changing behavior or infrastructure.
3. Read [.github/workflows/](.github/workflows/) for the actual promotion and deployment gates.
4. Read [changelog/README.md](changelog/README.md) only when implementation, incident, deployment, or operational history matters.

`Codex.md` is a compatibility pointer with durable decisions; it is not required after this file.

## Shared contracts

- Auth profile registry: https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/17-auth-profile-registry.md
- Protected feature contract: https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/19-protected-feature-contract.md
- Fleet ownership: https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/repository-map.md

The hub owns browser-safe cross-repository contracts. This repository remains canonical for auth-admin implementation, session and authorization behavior, storage boundaries, deployment, and rollback.

## Non-negotiable security boundaries

- Own only the exact `/auth/session/*`, `/auth/admin/*`, and six TEST-only
  `/auth-v2/session/*` routes declared in `template.yaml`. API Proxy alone owns
  `/auth-v2/runtime-config`. Never add a broad `/auth/*` or `/auth-v2/*`
  front-door rule that can consume Angular or another service's routes.
- Keep tenant, environment, Cognito, group, approval, and manageable-group policy in server-only `AUTH_ADMIN_CONFIG_JSON_BASE64`; browser input cannot select that policy.
- Return only the existing sanitized public account/session fields. Never expose raw identity-provider records, unnecessary PII, JWTs, access or refresh tokens, Cognito challenge sessions, cookies, secret references, table names, partition keys, or other internal storage metadata.
- Preserve `__Host-zlp_session` as `HttpOnly`, `Secure`, `SameSite=Lax`, and `Path=/`. Mutations require the matching readable CSRF cookie, `X-ZLP-CSRF`, and server-side CSRF hash. Challenge and enrollment cookies remain separate and short-lived.
- Require `X-ZLP-Domain` and `X-ZLP-Auth-Profile-Id`, compare them with the private session/profile, and keep session, user-state, and audit records isolated by the resolved draft/profile boundary.
- Re-read current user state and session version for admin access and mutations. Pending, suspended, group-removed, environment-mismatched, revoked, and expired sessions fail closed.
- Audit every admin mutation without raw request secrets or PII. The only v2
  browser exception for TOTP setup is the five-minute, single-use response from
  `POST /auth-v2/session/mfa/setup` after exact-origin and CSRF validation. It
  may contain the manual setup key but must use no-store/no-referrer headers and
  must never put that material in URLs, logs, analytics, screenshots, durable
  notes, or any other response.
- Keep `tools/provision_thn_owner.py` operator-only and TEST-only. Its exact
  group is `journal-owner`, its purpose is always `client-owner`, and it must
  retain the transactional singleton reservation and pre-mutation audit intent.
  Account, partition, and region are reviewed trust anchors, never caller/argv
  selectors. Reset must leave the owner disabled and delete TOTP with
  `AdminDeleteSoftwareToken`. The CLI may call only the exact versioned alias's
  `AWS_IAM` function URL. Both identity and resource policies must restrict
  `lambda:InvokeFunction` with `lambda:InvokedViaFunctionUrl=true`; direct and
  asynchronous invoke remain denied. The URL is buffered, has no CORS, and the
  mediator has no API route, custom domain, DLQ, or destination. Neither surface
  may invoke or edit `zoolanding-cognito-user-lifecycle`. Keep the human role
  free of direct Cognito/DynamoDB/CloudFormation permissions. Describe the audit
  as append-only against that human role, not as WORM against authorized deployers.

## Development and release

- Create feature branches from current `dev`; promote only through separate `dev -> test -> main` pull requests. Preserve OIDC, GitHub Environments, merge-commit guards, stack names, and SAM config environments.
- Do not deploy, mutate Cognito/DynamoDB, enable PITR, change repository settings, or use real configuration values without explicit approval for that operation.
- Keep unit tests offline. Default closeout:

```powershell
python -m unittest discover -s tests -p "test_*.py"
pip-audit -r requirements.txt
pip-audit -r requirements-tools.txt
sam validate
actionlint -no-color
```

- `tools/check_auth_admin_readiness.py` is read-only unless `--enable-pitr` is explicitly approved for confirmed stack-owned tables. Report unavailable tools; never count a skipped check as passing.

## Knowledge and scratch

- Keep current behavior in README, code, template, workflows, and tests. Put dated evidence in `changelog/`, not here or in `Codex.md`.
- Keep `.superpowers/` and `devonly/` local and ignored. Never commit secrets, raw environment values, logs, local databases, or generated credential/config files.
