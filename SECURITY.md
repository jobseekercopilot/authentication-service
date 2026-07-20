# Security policy

This repository is private. Report suspected vulnerabilities privately to the
repository owner. Do not open a public issue or include credentials, tokens,
personal data, exploit details, or production logs in an issue.

Do not commit secrets. Use runtime environment variables or the approved
secret-management mechanism. If a credential may have been exposed, stop its
use, report the type and affected location without reproducing its value, and
arrange rotation with the owner.

For the current local-only environment, `JWT_SIGNING_KEY` is generated into an
ignored owner-readable `.env` file and injected by Compose. It must contain at
least 32 UTF-8 bytes. Missing, blank and weak values fail startup. Tests use
separate non-runtime material; keys, passwords and complete JWTs must never be
logged. Replacing the local key invalidates issued local JWTs and requires users
to authenticate again. Compromised or previous keys must not be restored.

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
