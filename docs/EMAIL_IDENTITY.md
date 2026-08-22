# Email identity policy

Authentication stores two representations of an email address:

- `email` is the display value returned to its owner. Leading/trailing Unicode
  space is removed and canonically equivalent Unicode is composed with NFC;
  casing and otherwise meaningful user input are preserved.
- `canonical_email` is the private lookup key. It applies Unicode NFKC,
  lowercases with `Locale.ROOT`, and converts an internationalised domain to
  its ASCII IDNA form. A unique, non-null database constraint enforces one
  account per canonical identity.

Registration, login, duplicate checks, environment-data seeding, and the local
login limiter all use the same canonical key. This prevents case, compatible
Unicode, composed/decomposed Unicode, internationalised-domain, and edge-space
variants from creating a second account or bypassing per-identity controls.
Only the display value is returned through the account API; neither form is
written to authentication decision logs.

This is an explicit product identity policy: the local part is treated as
case-insensitive. Provider-specific transformations are deliberately excluded.
In particular, dots are not removed and `+tag` suffixes are not stripped,
because those rules vary by provider and can merge distinct mailboxes.

Flyway V3 backfills existing rows with the application canonicalizer before it
adds the non-null unique constraint. If two existing rows collapse to one key,
the transaction fails with a redacted operator message and no schema/data
change. Operators must stop and resolve ownership through an approved account
support process before retrying. The migration never chooses an account or
deletes data automatically.

Tests cover display preservation, case, Unicode normalization, Unicode edge
space, IDNA equivalence, duplicate registration, variant login, shared limiter
identity, existing-row backfill, uniqueness, and collision rollback.

Residual risk: Unicode normalization cannot prevent every visually confusable
address, and changing this policy later is an identity migration requiring
collision analysis and explicit approval.
