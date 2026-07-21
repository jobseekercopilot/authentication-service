# Beta-readiness audit: authentication service

Audit date: 18 July 2026

Status: **Not beta-ready.** Adaptive password hashing, uniform authentication
failures, bounded local throttling, signed JWT expiry and migration-backed
PostgreSQL persistence are present. Token/session lifecycle and service endpoint
controls are now implemented; account lifecycle and broader full-path security
evidence remain blockers.

## Baseline and secret finding

Gitleaks found a generic API credential in the public root history at `.env`
(commit recorded in the private audit evidence) and false-positive example/test
tokens in authentication documentation/tests. The current authentication
configuration also contained a hard-coded JWT signing value. Imported private
history was rewritten to require `JWT_SECRET`; no value is reproduced here.
The owner confirmed that no AWS/application environment, production user or
production JWT currently exists. The historical key is permanently compromised
and must not be restored. AUTH-01 replaces local runtime material only; AWS and
production secret management remain outside the current system and scope.

The integration test could not bind an ephemeral socket in the restricted
sandbox; the approved host-network rerun then passed all 16 tests.

OWASP Dependency-Check 12.1.8 completed its initial NVD-backed analysis and
reported 10 dependency records with findings, including 17 Critical and 38
High entries before duplicate, reachability and false-positive triage. Two NVD
records failed database insertion because reference URLs exceeded the tool's
schema limit, and the unauthenticated OSS Index analyser was unavailable. The
result is a blocking, incomplete security baseline—not a clean scan.

## Findings

| ID | Finding | Evidence | Risk and severity | Recommended solution and acceptance criteria | Dependencies | Beta blocker | Effort |
|---|---|---|---|---|---|---|---|
| [AUTH-01](https://github.com/jobseekercopilot/authentication-service/issues/1) | Rotate exposed credentials and require managed JWT keys | `application.properties` contained a signing value; Gitleaks found a generic credential in public root `.env` history. | **Critical / P0 security:** public or reused credentials can enable account/data compromise or token forgery. | Rotate affected real credentials outside Git; require a sufficiently strong runtime secret with startup validation; document ownership/key rotation; prove no current/history Gitleaks finding except reviewed fixtures. | Owner rotation and secret store. | Yes | M |
| [AUTH-02](https://github.com/jobseekercopilot/authentication-service/issues/2) | Strengthen credentials and prevent account enumeration/brute force | **Remediated 2026-07-20:** 15–128 Unicode code points, local compromised-value checks, PBKDF2 with BCrypt migration, uniform failure paths and a bounded privacy-preserving limiter with automatic recovery are implemented and tested. A shared gateway/network limiter remains part of UMG-05 before scaling. | Resolved for the local beta path; distributed controls remain tracked at the gateway boundary. | Maintain the offline blocklist and re-evaluate limits before production or horizontal scaling. | UMG-04/05. | Yes | L |
| [AUTH-03](https://github.com/jobseekercopilot/authentication-service/issues/3) | Implement a complete token/session lifecycle | **Remediated:** access JWTs are short-lived and claim/algorithm constrained; hashed one-time refresh records rotate under a database lock; replay and logout revoke durable sessions. | **High / P1 security, mitigated:** browser cookie/storage adoption remains in CLIENT-02/03 and UMG-05. | Keep refresh material out of logs and JavaScript-readable storage; retain expiry, replay, logout and clock-skew tests. | Client/BFF session adoption. | No | XL |
| [AUTH-04](https://github.com/jobseekercopilot/authentication-service/issues/4) | Protect service and environment-data endpoints | **Remediated:** a deny-by-default stateless security chain requires a constant-time checked gateway identity on auth routes and a distinct environment-data identity on separately profile-guarded tooling; only health is public. Production config tests retain disabled H2/docs/Swagger and non-detailed health. | Shared-secret rotation requires a coordinated gateway/service restart until an overlap mechanism exists; platform network policy remains defence in depth. | Supply both identities from the runtime secret manager, restrict network reachability, rotate deliberately, and retain boundary/production-profile tests. | Gateway identity sender merged first. | No | L |
| [AUTH-05](https://github.com/jobseekercopilot/authentication-service/issues/5) | Replace H2/`ddl-auto=update` with production persistence and migrations | **Remediated:** PostgreSQL is the supported runtime, Flyway owns versioned schema changes, Hibernate validates only, and runtime SQL/H2 exposure is disabled. | Migration drift and weak runtime durability defaults are removed; managed provisioning and exercised environment restore remain operational responsibilities. | Retain empty/previous migration, constraint and isolated backup/restore tests; follow the database runbook for every release. | PostgreSQL platform provisioning and backup automation before deployment. | No | L |
| [AUTH-06](https://github.com/jobseekercopilot/authentication-service/issues/6) | Canonicalise email identity safely | **Remediated:** display and canonical representations are separate; all identity operations share an NFKC/case/IDNA key backed by a non-null unique constraint. | Duplicate/inaccessible case, Unicode and edge-space identities are prevented; visually confusable addresses remain a support risk. | Retain policy, integration and migration-collision regression tests; never add provider-specific rewriting without collision analysis. | AUTH-05 complete. | No | M |
| [AUTH-07](https://github.com/jobseekercopilot/authentication-service/issues/7) | Return stable non-leaking authentication errors | **Remediated:** known token and request failures map to stable versioned codes with correlation IDs; unknown failures return a redacted 500. | **High / P1 security/API, mitigated:** invalid tokens no longer become leaking parser/internal failures. | Keep version 1 codes backward compatible and use correlation IDs rather than exposing causes. | UMG-04 safe-error pattern complete. | No | M |
| [AUTH-08](https://github.com/jobseekercopilot/authentication-service/issues/8) | Decide and implement account lifecycle capabilities | Password change/reset, logout/revocation, deletion and retention/export flows are absent. | **High / P1 functional/privacy:** controlled-beta account support and deletion obligations are undefined. | Record beta decisions; implement required endpoints with re-authentication, audit events and tests, or explicitly defer with accepted risk/runbook. | AUTH-03 and privacy decision. | Yes | L |
| [AUTH-09](https://github.com/jobseekercopilot/authentication-service/issues/9) | Expand security and integration testing | No rate-limit, enumeration, cross-service auth, revocation, production-config or migration tests exist. | **High / P1 testing:** high-risk controls lack regression evidence. | Add unit/integration/contract/security tests plus full path coverage; run network-binding integration in CI. | AUTH-02–08. | Yes | L |
| [AUTH-10](https://github.com/jobseekercopilot/authentication-service/issues/10) | Harden container and documentation | **Remediated:** the image consumes a verified JAR, uses digest-pinned bases, runs as fixed non-root UID/GID with health/SIGTERM policy, receives final-image scanning, and documents actual proprietary runtime behavior. | The evidenced container/default/documentation risk is resolved; digest refresh, registry provenance and deployment orchestration remain operator-owned. | Keep verified-image, metadata and Critical/High scan gates required; refresh digests through reviewed PRs and retain graceful-shutdown smoke evidence. | AUTH-05 and AUTH-04 complete. | No | M |
| [AUTH-11](https://github.com/jobseekercopilot/authentication-service/issues/11) | Triage vulnerable dependencies and establish a reliable security gate | OWASP Dependency-Check reported 10 affected dependency records, including 17 Critical and 38 High entries before triage; two feed records failed processing, OSS Index lacked authentication, and CI only emits `mvn dependency:tree`. | **High / P1 dependency:** an authentication-facing vulnerable library can reach beta, while an incomplete feed can create false assurance. | Upgrade the Spring Boot/dependency baseline; triage duplicates, reachability and false positives with evidence; configure authenticated/cached advisory data; publish a machine-readable report; fail on unaccepted Critical/High findings and document risk acceptance. | Platform CI, advisory-feed and dependency-upgrade decisions. | Yes | L |
| [AUTH-12](https://github.com/jobseekercopilot/authentication-service/issues/20) | Prevent generated default security credentials | **Remediated:** the application annotation excludes Boot 4's default-user auto-configuration by class; no default user-details bean or browser authentication entry point exists. | The unintended credential provider and startup disclosure path are removed without changing the explicit service boundary. | Retain bean-absence, captured-startup and real HTTP regression tests in default and production-profile contexts. | AUTH-04 and AUTH-10 complete. | No | S |

## AUTH-01 remediation evidence

- Runtime configuration uses a required matching RSA private/public pair; no
  source fallback or hard-coded runtime value exists.
- Missing, malformed, mismatched and RSA keys below 2048 bits fail safely
  without including key material in the error.
- The local Compose path injects an ignored `.env` value generated without
  displaying it; `.env.example` is a blank placeholder only.
- Test-only signing material is isolated under `src/test` and is not reused by
  the local runtime.
- Token tests cover RS256, current/previous key success, unknown-key rejection,
  expiry and malformed input. Startup tests cover missing, malformed, weak and
  mismatched keys. Public JWKS responses contain no private key parameters.
- Full Maven, Compose authentication and complete-history secret-scan evidence
  is recorded in AUTH-01 and its pull request.

## AUTH-11 remediation evidence

- A fresh Trivy `rootfs` scan of all resolved runtime JARs reproduced 4
  Critical and 28 High findings on the Spring Boot 3.2.0 baseline.
- The service now uses the supported Spring Boot 4.1.0 BOM, springdoc 3.0.3,
  JJWT 0.13.0 and Lombok 1.18.46. Boot 4 rest-client APIs use their supported
  modules and package names.
- All 26 authentication tests and the Compose registration/login/current-user
  journey pass after the upgrade.
- The remediated scan covers 107 Java packages with no Critical or High
  findings and no accepted exceptions.
- CI caches current Trivy advisory data, uploads a JSON report, and rejects
  malformed/empty coverage or unaccepted Critical/High findings. Policy
  fixtures prove the negative paths and short-lived exception rules.

## AUTH-02 remediation evidence

- Registration enforces a 15–128 Unicode-code-point policy, basic bounded
  identity validation and local compromised/account-derived password checks
  without disclosing submitted passwords externally.
- New hashes use PBKDF2. Raw legacy BCrypt hashes remain verifiable and are
  transparently upgraded only following successful authentication.
- Unknown, wrong-password and inactive-account attempts follow the same failure
  response and generic log path; unknown accounts also perform a dummy hash
  verification.
- A bounded in-memory limiter uses only a digest of the normalized principal,
  blocks on the tenth failure by default, supplies `Retry-After`, clears on
  success and recovers automatically after 15 minutes.
- Unit and HTTP integration tests cover policy boundaries, Unicode, compromised
  values, uniform failures, hash migration, threshold behavior, recovery and
  invalid limiter configuration. Compose and scan evidence is recorded in
  AUTH-02 and its pull request.

## AUTH-07 remediation evidence

- Error responses use schema version 1 with a stable code, safe display
  message, timestamp and the same correlation ID returned in the response
  header.
- Missing, expired, malformed, unsupported and invalid tokens return explicit
  `401` codes. Credential failures remain uniform; validation, conflict,
  throttling, not-found and unexpected paths also have stable status/code pairs.
- The catch-all response never contains the exception message or cause. Logs
  record only the exception class and request metadata, never parser messages,
  credentials, signing keys or complete JWTs.
- HTTP integration tests cover every token category, alternate-key signatures,
  correlation propagation and response redaction; handler tests prove unknown
  exceptions cannot disclose internal details.

## AUTH-05 remediation evidence

- PostgreSQL 17 is the supported runtime database; direct local and Compose
  paths use PostgreSQL while H2 is restricted to the test classpath.
- Flyway migrations create the constrained users schema and its operational
  index. Hibernate uses `validate`; SQL value logging and the H2 console are off.
- The production profile requires explicit PostgreSQL configuration and
  nonblank credentials without echoing values. Swagger and detailed health are
  disabled there; AUTH-04 now enforces the wider endpoint boundary.
- Disposable PostgreSQL tests migrate an empty database and version 1 to the
  latest version, prove unique identity enforcement and data preservation, and
  restore a custom-format backup into a separate database.
- `docs/DATABASE_OPERATIONS.md` records deployment, backup, restore, rollback,
  ownership, legacy-H2 handling, deletion safety and residual platform work.

## AUTH-10 remediation evidence

- Docker consumes only the JAR produced by complete Maven verification; the
  previous test-skipping in-image Maven build is removed.
- Temurin and PostgreSQL references retain readable tags but are locked to
  reviewed registry digests. The Java process runs as UID/GID `10001:10001`.
- Image metadata tests enforce non-root identity, anonymous redacted health,
  SIGTERM, port, proprietary licence and absence of secret-variable history.
- Compose health, read-only/no-capability runtime restrictions, authenticated
  registration/login/me smoke and graceful shutdown were exercised together.
- Required CI builds and scans the final OS/library image only after verification
  and full-history secret scanning. `docs/CONTAINER_OPERATIONS.md` records safe
  refresh, rollback, ownership and residual platform responsibilities.

## AUTH-12 remediation evidence

- `AuthenticationServiceApplication` excludes Boot 4's
  `UserDetailsServiceAutoConfiguration` by class, so package drift becomes a
  compilation failure rather than a silently ignored property string.
- Default/test and production-profile contexts assert that no
  `UserDetailsService` bean exists and captured startup output contains neither
  the former credential notice nor the unintended in-memory provider name.
- Real HTTP tests prove Basic credentials and form posts cannot create a browser
  authentication path. The service-token boundary, separate environment-data
  identity, deny-by-default routing and anonymous redacted health remain intact.

## AUTH-06 remediation evidence

- One canonicalizer strips Unicode edge space, applies NFKC and locale-stable
  lowercase, and converts internationalised domains to their ASCII IDNA form.
- Registration, login, duplicate detection, environment-data seeding and the
  login limiter use `canonical_email`; the owner-facing API preserves the NFC
  display address and does not expose the internal lookup key.
- Flyway V3 backfills existing rows transactionally and adds a non-null unique
  constraint. A legacy collision aborts with a redacted error and no deletion
  or automatic account choice.
- Unit, HTTP and real PostgreSQL tests cover case, Unicode, whitespace, IDNA,
  duplicates, display preservation, backfill, uniqueness and collision rollback.
- `docs/EMAIL_IDENTITY.md` records the exact policy, excluded provider-specific
  rewrites, operational collision handling and residual confusable-address risk.

AUTH-01, AUTH-02, AUTH-03, AUTH-04, AUTH-05, AUTH-06, AUTH-07, AUTH-10,
AUTH-11 and AUTH-12 are resolved. Account lifecycle, distributed gateway
controls and production provisioning remain open, so the service is still
**not beta-ready**.
