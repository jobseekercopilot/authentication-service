# Authentication Service

## Role in Job Seeker Copilot

| Role | Called by | Calls | Data | Local port |
|---|---|---|---|---:|
| Account, credential, session and JWT issuer service | User Management Gateway; resource services read JWKS | User Profile, Application Tracker and Document Store for account lifecycle | Own PostgreSQL database | 8084 |

See the central [account journey](https://docs.jobseekercopilot.com/journeys/account-authentication/), [data ownership](https://docs.jobseekercopilot.com/data/ownership/), and [service catalogue](https://docs.jobseekercopilot.com/services/catalogue/).

Spring Boot service for account registration, adaptive password verification,
short-lived access/refresh session issue, rotation, revocation and current-account lookup.

> Delivery status: implemented, composed and exercised for the controlled
> private-beta account/session journey. Production account-lifecycle deployment
> evidence and broader security assurance remain outstanding. See
> [the audit](docs/BETA_READINESS_AUDIT.md).

Authentication's token-issuer responsibility and its boundary with Job Search
resource services are defined in the Infrastructure
[Job Search architecture ADR](https://github.com/jobseekercopilot/infrastructure/blob/develop/docs/adr/0001-job-search-architecture-and-ownership.md).

## Requirements and configuration

- Java 17 and Maven 3.9
- a matching RSA private/public key pair of at least 2048 bits
- PostgreSQL 17 (provided by Docker Compose for the local container journey)
- OpenSSL for local key generation; `curl` and `jq` for the smoke test
- Docker for the verified non-root image and Compose journey

| Variable/property | Local default | Purpose |
|---|---|---|
| `SERVER_PORT` | `8084` | HTTP port |
| `SPRING_PROFILES_ACTIVE` | `local` for direct JVM; Compose sets `production` | Configuration boundary |
| `AUTH_DB_URL` | local PostgreSQL URL | PostgreSQL JDBC URL |
| `AUTH_DB_USERNAME` | `authentication` locally | Database principal |
| `AUTH_DB_PASSWORD` | none; required | Database secret |
| `JWT_PRIVATE_KEY_BASE64` | none; required | PKCS#8 DER RSA private signing key, Base64 encoded |
| `JWT_PUBLIC_KEY_BASE64` | none; required | Matching X.509 DER RSA public key, Base64 encoded |
| `JWT_PREVIOUS_PUBLIC_KEYS` | blank | Rotation overlap as comma-separated `kid=base64-public-key` entries |
| `AUTH_SERVICE_TOKEN` | none; required | Minimum 32-byte identity shared only with user-management-gateway |
| `AUTH_ENVIRONMENT_DATA_TOKEN` | none; required | Distinct minimum 32-byte identity for non-production system-data tooling |
| `JWT_ACCESS_TOKEN_EXPIRATION_MS` | `900000` (15 minutes) | Access-token lifetime; startup rejects values above one hour |
| `JWT_ISSUER` | `job-seeker-copilot-authentication` | Required access-token issuer |
| `JWT_AUDIENCE` | `job-seeker-copilot-services` | Required access-token audience |
| `JWT_KEY_ID` | `primary` | Signing-key identifier placed in `kid` |
| `JWT_CLOCK_SKEW_SECONDS` | `30` | Accepted clock skew; maximum 300 seconds |
| `AUTH_REFRESH_TOKEN_LIFETIME` | `7d` | Absolute server-side session and refresh lifetime |
| `AUTH_LOGIN_MAXIMUM_FAILURES` | `10` | Failed logins allowed per normalized principal and attempt window |
| `AUTH_LOGIN_ATTEMPT_WINDOW` | `15m` | Window in which failed logins accumulate |
| `AUTH_LOGIN_LOCK_DURATION` | `15m` | Automatic recovery delay after the threshold |
| `AUTH_LOGIN_MAXIMUM_TRACKED_PRINCIPALS` | `10000` | Memory bound for locally tracked principals |
| `AUTH_PASSWORD_RESET_TOKEN_LIFETIME` | `30m` | Single-use reset-token lifetime |
| `AUTH_PASSWORD_RESET_REQUEST_COOLDOWN` | `60s` | Per-account reset-email cooldown |
| `AUTH_ACCOUNT_EMAIL_DELIVERY_MODE` | `fixture` | `fixture` for local/E2E; `ses` for hosted beta |
| `AUTH_ACCOUNT_EMAIL_APPLICATION_BASE_URL` | `http://localhost:4200` | Reset-link application origin; hosted value is `https://app.jobseekercopilot.com` |
| `AUTH_ACCOUNT_EMAIL_SENDER` | `accounts@jobseekercopilot.com` | Dedicated account-email sender |
| `AUTH_ACCOUNT_EMAIL_SUPPORT_URL` | `https://jobseekercopilot.com/contact` | Manual support route |
| `AUTH_ACCOUNT_EMAIL_SES_REGION` | `eu-west-2` | SES adapter region |
| `AUTH_ACCOUNT_EMAIL_SES_CONFIGURATION_SET` | `JobSeekerCopilotAccountEmails` | Dedicated account-email configuration set |

There is no fallback signing key. Missing, malformed, mismatched and RSA keys
below 2048 bits fail startup without echoing key material.
The local key belongs only in the ignored `.env` file generated below.

## API, health and build

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout` with bearer token
- `GET /api/auth/account/export` with a recently created bearer session
- `DELETE /api/auth/account` with a recently created bearer session and `Idempotency-Key`
- `POST /api/auth/password-reset/request`
- `POST /api/auth/password-reset/complete`
- `GET /api/auth/me` with bearer token
- `GET /.well-known/jwks.json` (public verification keys, cacheable for 5 minutes)
- `/actuator/health` (unauthenticated health route)

Every `/api/auth/**` request also requires `X-Service-Token`; this is injected
by user-management-gateway and is not a browser credential. The separately
guarded `/internal/system-data/**` routes require `X-Environment-Data-Token`
and remain disabled unless the environment-data profile/property policy permits
them. The two values must be distinct and at least 32 bytes. Requests to all
other routes are denied by default. CORS is not enabled because callers are
server-side services, and CSRF is disabled because this service does not accept
cookie authentication.

OpenAPI and Swagger are available only outside production for trusted local
development and require the service identity header. H2, API docs, Swagger UI
and detailed health are disabled in the production profile.

The reviewed producer contract is tracked in
[`contracts/openapi.json`](contracts/openapi.json), with its digest in
[`contracts/SHA256SUMS`](contracts/SHA256SUMS). Normal tests export the running
application's OpenAPI document and fail on semantic drift; see
[`contracts/README.md`](contracts/README.md) for the intentional update process.

Authenticated account export and coordinated retry-safe deletion are described
in [`docs/ACCOUNT_LIFECYCLE.md`](docs/ACCOUNT_LIFECYCLE.md). They require a
session created within the last 15 minutes. Deletion immediately revokes login,
then resumes any incomplete downstream steps from a content-free journal;
production irreversible document purge remains separately disabled.

Password-reset initiation returns the same `202` body for known and unknown
accounts. Eligible accounts receive a 32-byte opaque token in a URL fragment;
only its SHA-256 digest is stored. Tokens expire after 30 minutes, are
single-use, and an eligible newer request invalidates older unused tokens.
Completion locks the token and account in one transaction, changes the
password, consumes the token and revokes every active session. Rejected
passwords roll the transaction back without consuming the link.

Local and automated environments use the guarded in-memory fixture sender and
never contact SES. The hosted adapter uses the AWS SDK default backend
credential chain, the dedicated sender/configuration set and a
`message-purpose` tag. Neither AWS credentials nor reset material enters the
browser bundle or application logs.

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

Login and refresh return `token` (the access JWT), `refreshToken`, `tokenType`
and `expiresIn` seconds. `token` remains the access-token field for gateway
compatibility. Refresh tokens are opaque, rotate on every use and are stored
only as SHA-256 hashes. Reusing a consumed refresh token revokes its whole
session. Logout also revokes the server-side session, so an otherwise unexpired
access token immediately fails validation. Browser code must not persist either
token: the later BFF/client work owns its Secure, HttpOnly cookie boundary. See
[session security](docs/SESSION_SECURITY.md) for the contract and threat model.

```bash
mvn -B verify
./scripts/test-dependency-report-policy.sh
docker build -t authentication-service:local .
./scripts/verify-container-image.sh authentication-service:local
./scripts/generate-local-signing-key.sh
docker compose up --build --detach
./scripts/smoke-test-auth.sh
docker compose down
```

The image build deliberately consumes only the JAR produced by the preceding
`mvn verify`; it does not contain a second test-skipping Maven build. Runtime and
Compose bases are digest-pinned, the service runs as UID/GID `10001` with no
Linux capabilities in Compose, and the health check exercises the redacted
anonymous actuator endpoint. SIGTERM receives up to 30 seconds of Spring
graceful shutdown inside a 35-second Compose stop window. See
[container operations](docs/CONTAINER_OPERATIONS.md) for image refresh,
verification, scanning, startup and rollback ownership.

The generator creates a 3072-bit RSA pair in `.env` with owner-only permissions
and never prints its private key or local database password. Compose requires
the values from that file and injects them into the relevant containers. `.env.example`
contains deliberately blank placeholders. Tests use separate, clearly
non-runtime material under `src/test`; CI therefore needs no persistent secret.

Registration accepts passwords containing 15–128 Unicode code points and does
not impose composition rules. Common compromised values and values based on
account details are rejected locally; passwords are never sent to a third-party
checking service. New passwords use PBKDF2, while a successful login with a
legacy BCrypt hash transparently upgrades that hash. Login failures do not
disclose whether an account exists or is inactive.

Email display casing is preserved, while registration, login, uniqueness, and
local throttling use one migration-backed canonical identity across case,
Unicode normalization, internationalised-domain, and edge-space variants.
Provider-specific dot and `+tag` rewriting is not performed. See the
[email identity policy](docs/EMAIL_IDENTITY.md) for the exact rules, migration
collision behavior, security rationale, tests, and residual risk.

Failed logins are tracked by a SHA-256 digest of the normalized email, not the
email itself. The local service blocks at the configured threshold and returns
HTTP `429` with `Retry-After`; access recovers automatically after the lock
duration. This is a per-process safety control, so a future horizontally scaled
deployment also requires an owner-approved shared limiter. See
[credential security](docs/CREDENTIAL_SECURITY.md) for policy and trade-offs.

For non-disruptive rotation, choose a new `JWT_KEY_ID`, configure the old public
key in `JWT_PREVIOUS_PUBLIC_KEYS`, deploy the new pair, and retain the old public
key for at least the maximum access-token lifetime plus clock skew and JWKS cache
age. Then remove it. Previous private keys must never be retained or published.

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
finding. The current supported baseline is Spring Boot 4.1.0 with PostgreSQL
JDBC 42.7.12 and no accepted dependency exceptions. A separate required job
rebuilds the JAR with complete verification, builds the final image, asserts
its runtime metadata, scans OS and library packages, and applies the same
Critical/High policy. Reproduction, ownership and the short-lived exception
process are documented in
[the dependency security runbook](docs/DEPENDENCY_SECURITY.md).

## Branch workflow and troubleshooting

Use `feature/* → develop`; `main` will be added later as a release branch. A
startup failure mentioning JWT RSA key configuration means the private/public
pair is missing, malformed, weak or mismatched. Authentication failures must be
diagnosed through correlation IDs, never by logging emails, passwords, signing keys or complete
tokens. Use the response `code` for client behavior and the correlation ID for
diagnosis; messages are safe display text rather than internal diagnostics. Do
not raise login thresholds casually: lower values increase denial-of-
service risk, while higher values allow more automated guesses.

## Licence

Copyright © 2026 Bernard McGeever. All rights reserved.

This repository contains proprietary software belonging to Bernard McGeever.
It may not be used, copied, modified or distributed without express written
permission. See [LICENSE](./LICENSE).
