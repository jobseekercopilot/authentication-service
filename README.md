# Authentication Service

Spring Boot service for account registration, adaptive password verification,
JWT access-token issue and current-account lookup.

> Beta status: not beta-ready. Token lifecycle, endpoint controls, account
> lifecycle, and broader security coverage remain blockers. See
> [the audit](docs/BETA_READINESS_AUDIT.md).

## Requirements and configuration

- Java 17 and Maven 3.9
- a runtime JWT signing key containing at least 32 UTF-8 bytes
- PostgreSQL 17 (provided by Docker Compose for the local container journey)
- OpenSSL for local key generation; `curl` and `jq` for the smoke test

| Variable/property | Local default | Purpose |
|---|---|---|
| `SERVER_PORT` | `8084` | HTTP port |
| `SPRING_PROFILES_ACTIVE` | `local` for direct JVM; Compose sets `production` | Configuration boundary |
| `AUTH_DB_URL` | local PostgreSQL URL | PostgreSQL JDBC URL |
| `AUTH_DB_USERNAME` | `authentication` locally | Database principal |
| `AUTH_DB_PASSWORD` | none; required | Database secret |
| `JWT_SIGNING_KEY` | none; required | Access-token signing key (minimum 32 UTF-8 bytes) |
| `jwt.expiration` | `86400000` | Temporary access-token lifetime (ms) |
| `AUTH_LOGIN_MAXIMUM_FAILURES` | `10` | Failed logins allowed per normalized principal and attempt window |
| `AUTH_LOGIN_ATTEMPT_WINDOW` | `15m` | Window in which failed logins accumulate |
| `AUTH_LOGIN_LOCK_DURATION` | `15m` | Automatic recovery delay after the threshold |
| `AUTH_LOGIN_MAXIMUM_TRACKED_PRINCIPALS` | `10000` | Memory bound for locally tracked principals |

There is no fallback signing key. Missing, blank and weak values fail startup
without echoing key material. Never reuse the compromised historical value.
The local key belongs only in the ignored `.env` file generated below.

## API, health and build

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me` with bearer token
- `/v3/api-docs`, `/swagger-ui/index.html`, `/actuator/health`

Failures use a stable version 1 JSON contract:

```json
{
  "schemaVersion": "1",
  "code": "TOKEN_EXPIRED",
  "message": "The authentication token has expired.",
  "correlationId": "<X-Correlation-Id response value>",
  "timestamp": "<UTC timestamp>"
}
```

Missing, expired, malformed, unsupported and invalid tokens return `401` with
`TOKEN_REQUIRED`, `TOKEN_EXPIRED`, `TOKEN_MALFORMED`, `TOKEN_UNSUPPORTED` and
`TOKEN_INVALID`. Credential failures remain uniformly
`AUTHENTICATION_FAILED`; validation, conflict, throttling and unexpected errors
use `REQUEST_VALIDATION_FAILED`, `ACCOUNT_ALREADY_EXISTS`,
`TOO_MANY_AUTHENTICATION_ATTEMPTS` and `INTERNAL_ERROR`. Parser messages,
exception causes, credentials and complete tokens are never returned.

```bash
mvn -B verify
./scripts/test-dependency-report-policy.sh
./scripts/generate-local-signing-key.sh
docker compose up --build --detach
./scripts/smoke-test-auth.sh
docker compose down
```

The generator creates `.env` with owner-only permissions and never prints its
generated signing key or local database password. Compose requires both values
from that file and injects them into the relevant containers. `.env.example`
contains deliberately blank placeholders. Tests use separate, clearly
non-runtime material under `src/test`; CI therefore needs no persistent secret.

Registration accepts passwords containing 15–128 Unicode code points and does
not impose composition rules. Common compromised values and values based on
account details are rejected locally; passwords are never sent to a third-party
checking service. New passwords use PBKDF2, while a successful login with a
legacy BCrypt hash transparently upgrades that hash. Login failures do not
disclose whether an account exists or is inactive.

Failed logins are tracked by a SHA-256 digest of the normalized email, not the
email itself. The local service blocks at the configured threshold and returns
HTTP `429` with `Retry-After`; access recovers automatically after the lock
duration. This is a per-process safety control, so a future horizontally scaled
deployment also requires an owner-approved shared limiter. See
[credential security](docs/CREDENTIAL_SECURITY.md) for policy and trade-offs.

To rotate the local key, stop the Compose service, remove or archive `.env`
outside the repository, rerun the generator, and recreate the container.
Replacing the key invalidates every existing local JWT, so developers must log
in again. Never restore or reuse an exposed previous key.

For a direct local process, start PostgreSQL, load the ignored `.env` into the
process environment, and then run `mvn spring-boot:run`. Do not put secret
values on the command line, in documentation, or in logs.

PostgreSQL is the supported local-container and production database. Flyway
owns schema changes and Hibernate only validates them; H2 is test-scoped. SQL
value logging and the H2 console are disabled. The production profile requires
an explicit PostgreSQL URL and nonblank credentials, and disables Swagger plus
detailed health output. See the
[database operations runbook](docs/DATABASE_OPERATIONS.md) for migrations,
backup/restore, rollback, ownership, legacy local H2 handling, and residual risk.

CI scans the resolved runtime dependency set with pinned Trivy, uploads a JSON
report, and fails closed on missing coverage or any unaccepted Critical/High
finding. The current supported baseline is Spring Boot 4.1.0 with no accepted
dependency exceptions. Reproduction, ownership and the short-lived exception
process are documented in
[the dependency security runbook](docs/DEPENDENCY_SECURITY.md).

## Branch workflow and troubleshooting

Use `feature/* → develop`; `main` will be added later as a release branch. A
startup failure mentioning `jwt.signing-key` means `JWT_SIGNING_KEY` was not
supplied or was too weak. Authentication failures must be diagnosed through
correlation IDs, never by logging emails, passwords, signing keys or complete
tokens. Use the response `code` for client behavior and the correlation ID for
diagnosis; messages are safe display text rather than internal diagnostics. Do
not raise login thresholds casually: lower values increase denial-of-
service risk, while higher values allow more automated guesses.

## Licence

Copyright © 2026 Bernard McGeever. All rights reserved.

This repository contains proprietary software belonging to Bernard McGeever.
It may not be used, copied, modified or distributed without express written
permission. See [LICENSE](./LICENSE).
