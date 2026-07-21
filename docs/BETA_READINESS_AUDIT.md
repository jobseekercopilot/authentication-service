# Beta-readiness audit: authentication service

Audit date: 18 July 2026

Status: **Not beta-ready.** Adaptive password hashing, uniform authentication
failures, bounded local throttling, signed JWT expiry and migration-backed
PostgreSQL persistence are present, but token lifecycle and endpoint controls
remain blockers.

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
| [AUTH-03](https://github.com/jobseekercopilot/authentication-service/issues/3) | Implement a complete token/session lifecycle | JWT has only subject/iat/exp, lasts 24 hours, and has no issuer, audience, key ID, refresh rotation, revocation or server logout. | **High / P1 security:** stolen tokens remain usable and consumers cannot constrain issuer/audience. | Design short-lived access plus rotated refresh/session; validate issuer/audience/algorithm; support revocation/logout and rotation; test expiry, replay and clock skew. | Client session redesign. | Yes | XL |
| [AUTH-04](https://github.com/jobseekercopilot/authentication-service/issues/4) | Protect service and environment-data endpoints | The service uses crypto but no Spring Security filter chain; `/internal/system-data` is guarded only by profile/property logic; H2 console and detailed health are enabled. | **High / P1 security:** direct network access can bypass intended gateway controls and expose management/dev functions. | Deny direct public access, authenticate service calls, make internal endpoints separately authorised, disable H2/Swagger/detailed health in production and test the production profile. | Service identity/network design. | Yes | L |
| [AUTH-05](https://github.com/jobseekercopilot/authentication-service/issues/5) | Replace H2/`ddl-auto=update` with production persistence and migrations | **Remediated:** PostgreSQL is the supported runtime, Flyway owns versioned schema changes, Hibernate validates only, and runtime SQL/H2 exposure is disabled. | Migration drift and weak runtime durability defaults are removed; managed provisioning and exercised environment restore remain operational responsibilities. | Retain empty/previous migration, constraint and isolated backup/restore tests; follow the database runbook for every release. | PostgreSQL platform provisioning and backup automation before deployment. | No | L |
| [AUTH-06](https://github.com/jobseekercopilot/authentication-service/issues/6) | Canonicalise email identity safely | Registration/login trim but do not lower/canonicalise; database uniqueness is implementation/collation dependent. | **Medium / P1 data:** case variants can create duplicate or inaccessible identities. | Define canonicalisation and display preservation, enforce a canonical unique column and migrate/test case/Unicode/whitespace variants. | Database migration. | Yes | M |
| [AUTH-07](https://github.com/jobseekercopilot/authentication-service/issues/7) | Return stable non-leaking authentication errors | **Remediated:** known token and request failures map to stable versioned codes with correlation IDs; unknown failures return a redacted 500. | **High / P1 security/API, mitigated:** invalid tokens no longer become leaking parser/internal failures. | Keep version 1 codes backward compatible and use correlation IDs rather than exposing causes. | UMG-04 safe-error pattern complete. | No | M |
| [AUTH-08](https://github.com/jobseekercopilot/authentication-service/issues/8) | Decide and implement account lifecycle capabilities | Password change/reset, logout/revocation, deletion and retention/export flows are absent. | **High / P1 functional/privacy:** controlled-beta account support and deletion obligations are undefined. | Record beta decisions; implement required endpoints with re-authentication, audit events and tests, or explicitly defer with accepted risk/runbook. | AUTH-03 and privacy decision. | Yes | L |
| [AUTH-09](https://github.com/jobseekercopilot/authentication-service/issues/9) | Expand security and integration testing | No rate-limit, enumeration, cross-service auth, revocation, production-config or migration tests exist. | **High / P1 testing:** high-risk controls lack regression evidence. | Add unit/integration/contract/security tests plus full path coverage; run network-binding integration in CI. | AUTH-02–08. | Yes | L |
| [AUTH-10](https://github.com/jobseekercopilot/authentication-service/issues/10) | Harden container and documentation | Docker skips tests, runs as root on mutable images; README claims RBAC/CORS/Spring Security and MIT licensing that source does not implement. | **Medium / P1 devops/docs:** unsafe image defaults and misleading security claims. | Pin/scan images, use non-root, health check, graceful shutdown, run verify, and document actual config/operations/proprietary licence. | AUTH-05. | Yes | M |
| [AUTH-11](https://github.com/jobseekercopilot/authentication-service/issues/11) | Triage vulnerable dependencies and establish a reliable security gate | OWASP Dependency-Check reported 10 affected dependency records, including 17 Critical and 38 High entries before triage; two feed records failed processing, OSS Index lacked authentication, and CI only emits `mvn dependency:tree`. | **High / P1 dependency:** an authentication-facing vulnerable library can reach beta, while an incomplete feed can create false assurance. | Upgrade the Spring Boot/dependency baseline; triage duplicates, reachability and false positives with evidence; configure authenticated/cached advisory data; publish a machine-readable report; fail on unaccepted Critical/High findings and document risk acceptance. | Platform CI, advisory-feed and dependency-upgrade decisions. | Yes | L |

## AUTH-01 remediation evidence

- Runtime configuration uses required `JWT_SIGNING_KEY`; no source fallback or
  hard-coded runtime value exists.
- Missing, blank and values shorter than 32 UTF-8 bytes fail safely without
  including key material in the error.
- The local Compose path injects an ignored `.env` value generated without
  displaying it; `.env.example` is a blank placeholder only.
- Test-only signing material is isolated under `src/test` and is not reused by
  the local runtime.
- Token tests cover current-key success, different-key rejection, expiry and
  malformed input. Startup/configuration tests cover missing and weak keys.
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
  disabled there pending AUTH-04's wider endpoint controls.
- Disposable PostgreSQL tests migrate an empty database and version 1 to the
  latest version, prove unique identity enforcement and data preservation, and
  restore a custom-format backup into a separate database.
- `docs/DATABASE_OPERATIONS.md` records deployment, backup, restore, rollback,
  ownership, legacy-H2 handling, deletion safety and residual platform work.

AUTH-01, AUTH-02, AUTH-05, AUTH-07 and AUTH-11 are resolved. Token/session lifecycle,
distributed gateway controls and production provisioning remain open, so the
service is still **not beta-ready**.
