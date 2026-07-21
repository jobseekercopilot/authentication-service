# Container operations

The authentication image is a proprietary private-beta artifact. It is built
from a repository commit only after that commit's complete Maven verification.
It is not a production deployment definition.

## Verified build

Requirements are Java 17, Maven 3.9, Docker and `jq`:

```bash
mvn -B verify
docker build --tag authentication-service:local .
./scripts/verify-container-image.sh authentication-service:local
```

The Docker context excludes `target/` except for
`target/authentication-service-1.0.0.jar`. The Dockerfile therefore cannot
silently compile a different or test-skipped artifact. CI repeats verification,
builds the image, asserts its metadata, scans final OS and Java packages, uploads
the JSON report, and rejects unaccepted Critical/High findings.

The runtime image:

- pins the Temurin JRE base by digest;
- runs as fixed UID/GID `10001:10001`;
- declares a redacted `/actuator/health` health check;
- declares `SIGTERM` and starts Java directly;
- labels the licence as `LicenseRef-Proprietary`;
- contains no runtime signing, database, service-identity or environment-data
  credential.

Compose additionally pins PostgreSQL by digest, drops all service capabilities,
sets `no-new-privileges`, uses a read-only root filesystem with a bounded `/tmp`
tmpfs, and provides a minimal init process.

## Local startup and health

Generate ignored local credentials and start only the private local stack:

```bash
./scripts/generate-local-signing-key.sh
docker compose config --quiet
docker compose up --build --detach --wait
# Keep AUTH_SERVICE_TOKEN loaded in the shell without printing it.
./scripts/smoke-test-auth.sh
docker compose ps
```

The service health check calls `http://127.0.0.1:8084/actuator/health` from
inside the container. That endpoint is the only anonymous route, never returns
health details, and includes database health. Do not replace it with an endpoint
that requires a service credential or exposes configuration.

## Graceful shutdown

Spring uses graceful shutdown with a 30-second per-phase limit. Compose sends
SIGTERM and allows 35 seconds before forced termination:

```bash
docker compose stop authentication-service
docker compose logs authentication-service
docker compose down
```

A validation should confirm the service receives SIGTERM, exits within the stop
window, and does not log credentials or token material. Forced termination after
35 seconds is a failure to investigate; do not lengthen the window to hide stuck
requests.

## Digest refresh and rollback

The repository maintainer owns monthly and security-triggered digest review.
For each existing approved image tag:

1. Pull the tag and record its registry-reported digest without copying registry
   credentials into commands, logs or issues.
2. Review upstream release notes and provenance; do not introduce a new registry
   or paid dependency under a routine refresh.
3. Update only the readable `tag@sha256:digest` reference in a dedicated PR.
4. Run complete Maven verification, image build/metadata checks, Compose health
   and smoke/shutdown checks, dependency scan and final-image scan.
5. Merge only when required CI and full-history secret scanning pass.

Rollback is a normal PR restoring the last reviewed digest and rebuilding from
the same source commit. Never force-push or retag an existing immutable release.
Keep the prior digest and scan evidence in Git/CI rather than in a local secret
file. Production rollout or rollback is outside this runbook and requires its
own approval.

## Residual risks

Digest pinning fixes the reviewed base filesystem but does not prove publisher
identity or eliminate a vulnerability discovered later. The image build applies
current security updates from the base distribution repositories, so the stored
CI report—not the base digest alone—is the evidence for the resulting package
set. The CI scanner depends on its advisory feed, and local Compose is not a
production orchestrator. Registry signing/attestation, deployment resource
limits, network policy, external secret management, monitoring and production
rollback remain platform responsibilities.
