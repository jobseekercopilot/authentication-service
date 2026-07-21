# Authentication database operations

PostgreSQL 17 is the supported runtime database. Flyway is the sole schema
owner: application startup validates and applies the checked-in migrations,
while Hibernate is restricted to `validate`. H2 exists only on the test
classpath and is never packaged as a runtime database.

## Configuration and ownership

Set `SPRING_PROFILES_ACTIVE=production` and supply `AUTH_DB_URL`,
`AUTH_DB_USERNAME`, and `AUTH_DB_PASSWORD` through the environment's secret
manager. Production startup rejects non-PostgreSQL URLs and blank credentials
without including their values in the error. SQL value logging and the H2
console are disabled. API docs and detailed health output are also disabled by
the production profile; AUTH-04 retains the wider endpoint-authorisation work.

The service owner owns migrations and restore drills. The platform owner owns
database provisioning, encryption, network access, automated backups,
retention, monitoring, and credential rotation. Never commit a dump or place a
database password on a command line.

## Migration procedure

1. Review new `V*__*.sql` files as append-only changes. Never edit a migration
   already applied to a shared environment.
2. Run `mvn -B verify`; this starts disposable PostgreSQL, migrates an empty
   database and the previous schema version, verifies constraints/data
   retention, then completes a backup/restore into a separate database.
3. Take and verify a backup before an environment change.
4. Apply the release to one non-serving instance first. Flyway validates
   checksums and migrates before the application accepts traffic.
5. Confirm `/actuator/health`, registration, login, refresh rotation, logout, and current-user lookup
   before increasing traffic.

There are no automated down migrations. If an application rollback is needed,
restore the prior application only when its schema is forward compatible.
Otherwise stop writes and restore the pre-change backup into a newly provisioned
database, then repoint the service. An irreversible migration requires Bernard's
explicit approval before it is run.

## Backup and restore drill

Use secret-injected environment variables and write dumps only to an encrypted,
access-controlled location. A representative custom-format backup is:

```bash
pg_dump --format=custom --no-owner --no-acl \
  --dbname="$AUTH_DB_URL" --file=/secure/authentication.dump
```

Restore into a newly created, empty validation database—not over the source:

```bash
pg_restore --exit-on-error --no-owner --no-acl \
  --dbname="$AUTH_RESTORE_DB_URL" /secure/authentication.dump
```

After restore, verify Flyway history, account row counts, registration, login,
and authenticated lookup before any cutover. Record the dump identifier,
checksums, timestamps, migration version, test evidence, and deletion date.
Destroy the validation database and dump according to the approved retention
policy only after the drill is signed off.

The automated PostgreSQL test performs this drill with synthetic data in a
throwaway container and restores into a distinct database. It never reads or
modifies developer, staging, production, or user data.

Migration V4 adds `authentication_session` and one-time `refresh_token` rows.
Refresh-token plaintext is never stored; `token_hash` is a unique SHA-256 digest.
Session and token rows are account-owned and cascade only when an account is
deliberately deleted by a future approved lifecycle flow. Expired/revoked-row
retention and account deletion remain governed by AUTH-08; no automated purge is
introduced by this migration.

## Legacy local H2 data

Old file-backed H2 databases are not upgraded in place and are not mounted by
the new Compose stack. They were development-only, but may still contain
personal data. Do not copy them into PostgreSQL automatically. If any data must
be retained, stop and perform an owner-reviewed export, validation, and import;
otherwise preserve or securely dispose of it under the retention decision in
PROFILE-04. `docker compose down` retains the named PostgreSQL volume;
`docker compose down --volumes` deletes local account data and must be used only
when that deletion is intentional.
