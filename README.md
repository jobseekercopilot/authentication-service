# Authentication Service

Spring Boot service for account registration, BCrypt password verification,
JWT access-token issue and current-account lookup.

> Beta status: not beta-ready. Secret rotation, token lifecycle, brute-force
> protection and production persistence are blockers. See
> [the audit](docs/BETA_READINESS_AUDIT.md).

## Requirements and configuration

- Java 17 and Maven 3.9
- a runtime JWT signing secret of sufficient strength

| Variable/property | Local default | Purpose |
|---|---|---|
| `SERVER_PORT` | `8084` | HTTP port |
| `AUTH_DB_URL` | local file H2 | Local-only account database |
| `JWT_SECRET` | none; required | Access-token signing secret |
| `jwt.expiration` | `86400000` | Temporary access-token lifetime (ms) |

Do not reuse the public-history value. Supply secrets through the approved
runtime secret mechanism.

## API, health and build

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me` with bearer token
- `/v3/api-docs`, `/swagger-ui/index.html`, `/actuator/health`

```bash
JWT_SECRET='set-through-approved-secret-mechanism' mvn -B verify
JWT_SECRET='set-through-approved-secret-mechanism' mvn spring-boot:run
docker build -t authentication-service .
```

H2, its console and automatic schema update are local-development settings,
not a production configuration.

## Branch workflow and troubleshooting

Use `feature/* → develop`; `main` will be added later as a release branch. A
startup failure mentioning `jwt.secret` means the runtime secret was not
supplied. Authentication failures must be diagnosed through correlation IDs,
never by logging passwords or tokens.

## Licence

Copyright © 2026 Bernard McGeever. All rights reserved.

This repository contains proprietary software belonging to Bernard McGeever.
It may not be used, copied, modified or distributed without express written
permission. See [LICENSE](./LICENSE).
