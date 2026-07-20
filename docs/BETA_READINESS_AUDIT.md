# Beta-readiness audit: authentication service

Audit date: 18 July 2026

Status: **Not beta-ready.** BCrypt hashing and signed JWT expiry are present,
but signing-secret exposure, token lifecycle, brute-force resistance and
production persistence are blockers.

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
| [AUTH-02](https://github.com/jobseekercopilot/authentication-service/issues/2) | Strengthen credentials and prevent account enumeration/brute force | Minimum password is four; emails are checked with `contains("@")`; missing user and wrong password return distinguishable messages; no throttling exists. | **High / P1 security:** weak passwords, enumeration and automated guessing. | Agree policy, validate length/Unicode/compromised-password handling, use uniform auth failures, rate-limit with lockout safeguards and test attack thresholds. | UMG-04/05. | Yes | L |
| [AUTH-03](https://github.com/jobseekercopilot/authentication-service/issues/3) | Implement a complete token/session lifecycle | JWT has only subject/iat/exp, lasts 24 hours, and has no issuer, audience, key ID, refresh rotation, revocation or server logout. | **High / P1 security:** stolen tokens remain usable and consumers cannot constrain issuer/audience. | Design short-lived access plus rotated refresh/session; validate issuer/audience/algorithm; support revocation/logout and rotation; test expiry, replay and clock skew. | Client session redesign. | Yes | XL |
| [AUTH-04](https://github.com/jobseekercopilot/authentication-service/issues/4) | Protect service and environment-data endpoints | The service uses crypto but no Spring Security filter chain; `/internal/system-data` is guarded only by profile/property logic; H2 console and detailed health are enabled. | **High / P1 security:** direct network access can bypass intended gateway controls and expose management/dev functions. | Deny direct public access, authenticate service calls, make internal endpoints separately authorised, disable H2/Swagger/detailed health in production and test the production profile. | Service identity/network design. | Yes | L |
| [AUTH-05](https://github.com/jobseekercopilot/authentication-service/issues/5) | Replace H2/`ddl-auto=update` with production persistence and migrations | File H2, blank database password, SQL logging and Hibernate auto-update are defaults; no migration files or restore plan exist. | **High / P1 data/reliability:** schema drift, weak durability and accidental credential/PII logging. | Select supported production database, add versioned migrations and constraints, separate local/prod config, test backup/restore and migration from empty/previous schema. | Platform database decision. | Yes | L |
| [AUTH-06](https://github.com/jobseekercopilot/authentication-service/issues/6) | Canonicalise email identity safely | Registration/login trim but do not lower/canonicalise; database uniqueness is implementation/collation dependent. | **Medium / P1 data:** case variants can create duplicate or inaccessible identities. | Define canonicalisation and display preservation, enforce a canonical unique column and migrate/test case/Unicode/whitespace variants. | Database migration. | Yes | M |
| [AUTH-07](https://github.com/jobseekercopilot/authentication-service/issues/7) | Return stable non-leaking authentication errors | `validate` wraps token failures in `RuntimeException`; global catch returns `"unexpected" + ex.getMessage()`. | **High / P1 security/API:** invalid tokens can become 500 and leak parser/internal details. | Map known failures to stable 4xx error codes, redact internal causes, add correlation IDs and test malformed/expired/unsupported tokens. | Shared error contract. | Yes | M |
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

This resolves AUTH-01 only. Token/session lifecycle, error mapping, brute-force
protection, persistence and dependency findings remain open, so the service is
still **not beta-ready**.
