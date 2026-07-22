# Dependency vulnerability scanning

## Decision and remediation baseline

The authentication service uses Trivy `v0.72.0` through the full-SHA-pinned
Trivy Action. Trivy is Apache-2.0 licensed and is the scanner already adopted
for the user-management path. It scans the resolved Maven runtime dependency
set and does not require an NVD API key or repository secret.

The AUTH-11 baseline scan of Spring Boot 3.2.0 covered 88 Java packages and
reported 4 Critical and 28 High records. These were fixed rather than
suppressed by moving to the supported Spring Boot 4.1.0 BOM, springdoc 3.0.3,
JJWT 0.13.0 and Lombok 1.18.46. Spring Boot 4's supported rest-client modules
and package names replaced the removed Boot 3 APIs. The remediated scan covers
107 Java packages with no Critical or High findings. No exception is active.

On 2026-07-22, E2E-03's final-image scan identified `CVE-2026-54291` in
PostgreSQL JDBC 42.7.11. The service explicitly overrides the BOM to reviewed
42.7.12, which contains the SCRAM-SHA-256-PLUS downgrade fix. A test asserts the
resolved runtime JAR version so a future BOM change cannot silently restore the
affected driver. No TLS, SCRAM or database authentication setting was relaxed.

## CI scope and failure behavior

The CI `verify` job:

1. runs `mvn -B verify` and the dependency-policy fixture suite;
2. materializes the resolved runtime JARs in an ignored scan-only directory;
3. scans those JARs with Trivy `rootfs`, listing packages without findings;
4. uploads the complete JSON report as
   `dependency-vulnerability-report-<commit>` for 30 days;
5. fails if the report is absent, malformed, has zero Java package coverage,
   or contains an unaccepted Critical or High finding.

Gitleaks separately scans complete Git history. Dependency scanning does not
replace authentication security tests, runtime hardening or secret scanning.

The required `container` job starts only after `verify` and `secrets` pass. It
repeats `mvn -B verify` to create the only JAR admitted by `.dockerignore`,
builds the final digest-pinned image, enforces non-root/health/SIGTERM/licence
metadata, scans both OS and library packages, uploads
`image-vulnerability-report-<commit>` for 30 days, and applies the same
Critical/High report policy. The duplicate verification is intentional: jobs
have isolated workspaces and the container job must not accept an unverified
artifact from another source.

The Trivy Action caches the vulnerability and Java advisory databases using
GitHub Actions cache rules and refreshes them from Aqua's public OCI mirrors.
A database download, scan, report upload or policy failure fails the job; CI
does not reuse a hand-maintained report or silently pass an empty scan.
Scanner and report-upload Actions are pinned to immutable commit SHAs.

## Local reproduction

Requirements are Java 17, Maven 3.9, Docker and `jq`:

```bash
mvn -B clean verify
./scripts/test-dependency-report-policy.sh
mvn -B dependency:copy-dependencies \
  -DincludeScope=runtime \
  -DoutputDirectory=target/dependency-scan
docker run --rm \
  -v "$PWD/target/dependency-scan:/scan/dependencies:ro" \
  -v "$PWD/config/trivy/.trivyignore:/scan/.trivyignore:ro" \
  -v "$PWD/target:/report" \
  aquasec/trivy:0.72.0 rootfs \
  --scanners vuln \
  --pkg-types library \
  --list-all-pkgs \
  --format json \
  --ignorefile /scan/.trivyignore \
  --output /report/trivy-dependencies.json \
  /scan/dependencies
./scripts/verify-dependency-report.sh \
  target/trivy-dependencies.json config/trivy/.trivyignore
```

Only the resolved JAR directory, the ignore file and the report directory are
mounted. Do not mount the repository or Docker socket into a scanner. Do not
commit generated reports or caches. Pull-request CI remains authoritative
because it runs from a clean checkout with current advisory data.

The final-image scan is normally reproduced by building from the verified JAR
and scanning `authentication-service:local` with Trivy 0.72.0. Do not grant a
third-party scanner the Docker socket and do not mount the repository. Where a
locally installed Trivy binary is unavailable, rely on the required clean CI
job rather than weakening isolation.

## Upgrade and risk-acceptance procedure

Prefer a supported BOM or direct-dependency upgrade. After an upgrade, review
release notes, run every authentication/security test, exercise the affected
full path, and rescan a freshly materialized runtime set. Do not suppress a
duplicate until package/version and reachability evidence prove it is not an
independent runtime risk.

An exception requires explicit repository-owner acceptance:

1. create or update a private dependency-security issue recording the finding,
   affected package/version, reachability, compensating controls, owner,
   remediation plan and review date;
2. put that issue URL immediately above one finding ID in
   `config/trivy/.trivyignore`;
3. add `exp:YYYY-MM-DD` no more than 30 days in the future;
4. submit the exception through review and attach the CI JSON report;
5. remove it by expiry or repeat owner review with new evidence.

Example syntax only:

```text
# Tracking: https://github.com/jobseekercopilot/authentication-service/issues/123
CVE-2099-12345 exp:2099-01-30
```

The policy rejects blanket package/path exclusions and untracked, undated,
expired or longer-than-30-day entries.

## Ownership and residual risk

The repository owner approves dependency changes and exceptions. GitHub hosts
the runner/cache; Aqua supplies scanner and advisory data. A clean report does
not prove the absence of unpublished flaws or runtime exploitability, and the
remaining non-blocking findings still require routine review. Large framework
upgrades require behavioral verification even when the vulnerability gate is
green.
