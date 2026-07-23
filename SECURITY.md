# Security policy

This repository is private. Report suspected vulnerabilities privately to the
repository owner. Do not open a public issue or include credentials, tokens,
personal data, exploit details, or production logs in an issue.

Do not commit secrets. Use runtime environment variables or the approved
secret-management mechanism. If a credential may have been exposed, stop its
use, report the type and affected location without reproducing its value, and
arrange rotation with the owner.

For the current local-only environment, a 3072-bit RSA pair is generated into an
ignored owner-readable `.env` file and injected by Compose. Missing, malformed,
mismatched and RSA keys below 2048 bits fail startup. Only public RSA material is
served by the JWKS endpoint; signing material remains private. Tests use
separate non-runtime material; keys, passwords and complete JWTs must never be
logged. A previous public key may be retained only for the documented bounded
rotation overlap; previous private keys must not be retained or restored.

No AWS or production secret store is configured. Adding one, deploying a
production environment, or rotating a deployed credential requires a separate
owner-approved operational change.

The current code is a beta-readiness baseline, not a security certification.
Known risks and beta blockers are tracked in `docs/BETA_READINESS_AUDIT.md`.

Resolved runtime dependencies are scanned in CI with pinned Trivy and a
machine-readable report. Missing/empty reports and unaccepted Critical/High
findings fail the build. Any temporary exception requires private owner review,
a tracking issue and an expiry of no more than 30 days; see
`docs/DEPENDENCY_SECURITY.md`. There are currently no accepted dependency
findings.

Credential handling follows `docs/CREDENTIAL_SECURITY.md`: 15–128 Unicode code
points, a local compromised-password blocklist, PBKDF2 for new hashes and
transparent BCrypt migration. Authentication failures are deliberately uniform.
Repeated failures are temporarily limited using a digest of the normalized
principal; the service must not log that principal, the supplied password, or
the reason an individual login failed. The in-memory limiter is a local-runtime
control, not a substitute for a shared edge/service limiter in a scaled
deployment.

CI scans the complete Git history with the pinned Gitleaks image through
`scripts/verify-secret-history.sh`. The scan fails closed when Git discovery
fails, the repository has no commits, Gitleaks rejects the history, or the
scanner does not report a non-zero commit count. Only the read-only checkout is
marked as a safe Git directory inside the disposable scanner container.
`scripts/test-secret-history.sh` verifies those controls with disposable
repositories, including a synthetic credential that is never added to this
repository.
