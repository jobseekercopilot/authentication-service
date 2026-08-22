# Public-beta account export and deletion

Status: AUTH-08 policy approved on 2026-08-07. This document separates the
public-beta implementation boundary from the later production irreversible
purge release gate.

## User contract

An authenticated user who has signed in within the last 15 minutes can:

- download one synchronous JSON export of Authentication, Profile,
  Application Tracker, Document Store and retained Payment records; and
- request account deletion with a retry-safe `Idempotency-Key`.

Export responses use `Cache-Control: no-store` and are not persisted by the
service. If a later implementation materialises export artifacts, they must be
private, encrypted, single-use and automatically expire; that is not part of
this synchronous implementation.

The export includes the immutable registration legal-document version,
acceptance timestamp, Terms acceptance, Privacy Notice acknowledgement and
18-or-over confirmation. This record is removed with the authentication
account after coordinated deletion completes. It also includes the user's
document-credit wallet and content-free payment ledger, order and provider
reconciliation evidence. It never includes card details, billing addresses,
payment-provider secrets or document content.

Recommended user-facing wording:

- Export: “Download a copy of your Job Seeker Copilot data. For your security,
  you may be asked to sign in again. Keep the downloaded file somewhere safe.”
- Delete: “Delete your account? You will be signed out and will no longer be
  able to access it. Your documents move to a 30-day recovery period. Legal
  holds and records needed to keep submitted application history accurate may
  be retained. This cannot be undone from your account.”
- Accepted: “Your account deletion has started. You have been signed out. If a
  service is temporarily unavailable, deletion will continue automatically.”
- Support: “If you believe deletion has not completed, contact support and
  provide the operation ID. Do not send document contents or passwords.”

Document archive, delete, recovery and tombstone wording is owned by DOC-09 in
Document Store's `docs/RETENTION_AND_PURGE.md` and must be used unchanged by
the client.

## Coordination and recovery

Authentication owns the durable deletion journal. Starting a request disables
the account, replaces identifying credentials, and revokes password-reset,
session and refresh material before any downstream erasure is attempted.
Downstream calls use a signed, operation-bound `account_lifecycle` JWT valid
for at most 15 minutes. That token is accepted only on dedicated internal
lifecycle routes and cannot call normal user APIs.

The coordinator runs in this order:

1. Payment Service revokes document-credit and Checkout access, expires any
   still-open Stripe Checkout sessions through its own retry-safe provider
   boundary, and retains the statutory financial/reconciliation record.
   Authentication never calls Stripe directly and does not checkpoint this
   step while provider-session expiry is pending.
2. Document Store applies DOC-09 recoverable deletion and preserves held
   records and truthful application-linked identity.
3. Application Tracker erases the account's application records, workflows,
   availability projections and append-only events through its narrowly scoped
   transactional erasure guard.
4. User Profile erases the profile, evidence revisions and snapshots.
5. Authentication removes the already-scrubbed user row and completes the
   journal.

Each completed step is checkpointed. A scheduled worker resumes only missing
steps; it never re-enables login. Unresolved records and cursors are retained
indefinitely. Completed, content-free lifecycle records expire after 365 days.
The journal stores a hash of the idempotency key and stable error codes, never
raw keys, access tokens, email addresses or document content.

## Retention and legal hold

Document deletion follows approved DOC-09 policy: 30-day recovery, 90-day
retention of completed operation journals, indefinite retention of unresolved
recovery records/cursors, 365-day content-free lifecycle audit, and protection
of application-used identity while supported application history exists.
Legal holds are retained and do not block closing the user's login account.
Payment records required for fraud, tax, accounting, refund, dispute and
provider reconciliation are retained for the configured statutory period;
retention does not preserve purchase or Checkout access.

Only the peer-approved retention-administrator procedure in Document Store may
apply/release a legal hold or invoke guarded purge. Support and operators must
not inspect content, edit databases manually, bypass a hold, or treat a
document identifier as ownership proof.

## Production release gate

Account closure and recoverable document deletion may ship to private beta.
Production irreversible purge remains disabled until peer-reviewed evidence
covers database backup expiry and restore isolation, object-store version
expiry, application/report log expiry, administrator credential deployment and
rotation, and the production-like recovery/purge exercise. Policy approval is
not evidence that these deployment controls exist.
