# Credential security

## Registration policy

- Passwords contain 15–128 Unicode code points. Spaces and all Unicode code
  points are permitted; there are no uppercase, digit or symbol composition
  rules, and the submitted password is not normalized or otherwise altered.
- A normalized copy is used only to compare against a local set of common
  compromised values and the user's name, email and email identity. No password
  or derivative is disclosed to an external password-checking service.
- Names contain 1–100 characters and email addresses must have a basic local and
  domain form within 254 characters. This validation protects service bounds;
  verification of email ownership is tracked separately.
- New password hashes use Spring Security's PBKDF2 configuration. Existing raw
  BCrypt hashes remain verifiable and are re-encoded with PBKDF2 only after a
  successful authentication.

The length, Unicode, blocklist and rate-limiting decisions follow the verifier
principles in NIST SP 800-63B-4. The small bundled blocklist protects this local
beta without transmitting secrets. Before production, the owner should approve
a maintained offline compromised-password dataset and its update process.

## Login failure and throttling policy

Unknown accounts, wrong passwords and inactive accounts all return HTTP `401`
with `Invalid email or password.` A dummy password hash is verified for unknown
accounts so that the control path performs comparable expensive work. Logs use
the same generic rejection event and contain neither account identifiers nor
passwords.

The default per-process threshold is ten failures for a normalized principal in
15 minutes. Reaching it returns HTTP `429`, including `Retry-After`, for 15
minutes. A successful login clears previous failures, and access automatically
recovers when the lock expires. Only a SHA-256 digest of the lower-cased, trimmed
email is retained in memory, and the map is bounded to 10,000 principals.

This avoids a permanent administrative lockout but remains susceptible to a
targeted temporary denial of service. It also cannot coordinate counters across
replicas. Before horizontal scaling or production use, add shared principal and
network-origin controls at the approved gateway/service boundary, with trusted
proxy handling, observability and an owner-approved recovery process.

## Safe authentication errors

Authentication failures return a versioned machine-readable code, a safe
display message and the same correlation ID carried in the response header.
Token parsing distinctions are limited to required, expired, malformed,
unsupported and otherwise invalid inputs; every one returns `401`. Unknown
exceptions return a generic `INTERNAL_ERROR` without their message or cause.

Logs record request metadata, correlation IDs, outcome categories, duration and
exception class only. They must not contain request/response bodies, email
addresses, passwords, signing keys, complete JWTs or parser messages. Use a
correlation ID to connect a client failure to these metadata-only events.

## Configuration and verification

Docker Compose reads these optional local `.env` settings and injects them into
the service:

| Variable | Default |
|---|---:|
| `AUTH_LOGIN_MAXIMUM_FAILURES` | `10` |
| `AUTH_LOGIN_ATTEMPT_WINDOW` | `15m` |
| `AUTH_LOGIN_LOCK_DURATION` | `15m` |
| `AUTH_LOGIN_MAXIMUM_TRACKED_PRINCIPALS` | `10000` |

Every value must be positive or startup fails safely. Run `mvn -B verify` for
policy boundaries, Unicode handling, compromised-password rejection, uniform
failure behavior, legacy-hash migration, threshold enforcement and automatic
recovery tests. The Compose smoke test covers registration and login with a
strong local-only password. Never put passwords, hashes, complete JWTs or the
JWT signing key in test output, logs, issues or documentation.
