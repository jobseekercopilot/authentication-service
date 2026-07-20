# Authentication Service

Spring Boot service for account registration, BCrypt password verification,
JWT access-token issue and current-account lookup.

> Beta status: not beta-ready. Token lifecycle, brute-force protection,
> production persistence and dependency remediation are blockers. See
> [the audit](docs/BETA_READINESS_AUDIT.md).

## Requirements and configuration

- Java 17 and Maven 3.9
- a runtime JWT signing key containing at least 32 UTF-8 bytes
- Docker Compose for the local container journey
- OpenSSL for local key generation; `curl` and `jq` for the smoke test

| Variable/property | Local default | Purpose |
|---|---|---|
| `SERVER_PORT` | `8084` | HTTP port |
| `AUTH_DB_URL` | local file H2 | Local-only account database |
| `JWT_SIGNING_KEY` | none; required | Access-token signing key (minimum 32 UTF-8 bytes) |
| `jwt.expiration` | `86400000` | Temporary access-token lifetime (ms) |

There is no fallback signing key. Missing, blank and weak values fail startup
without echoing key material. Never reuse the compromised historical value.
The local key belongs only in the ignored `.env` file generated below.

## API, health and build

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me` with bearer token
- `/v3/api-docs`, `/swagger-ui/index.html`, `/actuator/health`

```bash
mvn -B verify
./scripts/test-dependency-report-policy.sh
./scripts/generate-local-signing-key.sh
docker compose up --build --detach
./scripts/smoke-test-auth.sh
docker compose down
```

The generator creates `.env` with owner-only permissions and never prints the
value. Compose requires `JWT_SIGNING_KEY` from that file and injects it into the
authentication container. `.env.example` contains only a deliberately blank
placeholder. Tests use separate, clearly non-runtime signing material under
`src/test`; CI therefore does not need a persistent signing-key secret.

To rotate the local key, stop the Compose service, remove or archive `.env`
outside the repository, rerun the generator, and recreate the container.
Replacing the key invalidates every existing local JWT, so developers must log
in again. Never restore or reuse an exposed previous key.

For a direct local process, load the ignored `.env` into the process environment
before running `mvn spring-boot:run`. Do not put the value on the command line,
in documentation or in logs.

H2, its console and automatic schema update are local-development settings,
not a production configuration.

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
correlation IDs, never by logging passwords, signing keys or complete tokens.

## Licence

Copyright © 2026 Bernard McGeever. All rights reserved.

This repository contains proprietary software belonging to Bernard McGeever.
It may not be used, copied, modified or distributed without express written
permission. See [LICENSE](./LICENSE).
