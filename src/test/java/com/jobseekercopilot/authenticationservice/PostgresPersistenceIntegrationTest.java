package com.jobseekercopilot.authenticationservice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
class PostgresPersistenceIntegrationTest {

    @Container
    private static final PostgreSQLContainer POSTGRES =
            new PostgreSQLContainer("postgres:17-alpine")
                    .withDatabaseName("authentication")
                    .withUsername("authentication")
                    .withPassword("test-only-database-password");

    @BeforeEach
    void resetDatabase() {
        flyway().clean();
    }

    @Test
    void migratesAnEmptyPostgresDatabaseAndEnforcesIdentityConstraints() throws SQLException {
        assertEquals(3, flyway().migrate().migrationsExecuted);

        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    INSERT INTO users
                        (id, name, email, canonical_email, password_hash, created_at, active)
                    VALUES
                        ('first', 'First User', 'first@example.test', 'first@example.test',
                         'hash', CURRENT_TIMESTAMP, TRUE)
                    """);

            SQLException duplicate = org.junit.jupiter.api.Assertions.assertThrows(SQLException.class,
                    () -> statement.executeUpdate("""
                            INSERT INTO users
                                (id, name, email, canonical_email, password_hash, created_at, active)
                            VALUES
                                ('second', 'Second User', 'first@example.test', 'first@example.test',
                                 'hash', CURRENT_TIMESTAMP, TRUE)
                            """));
            assertEquals("23505", duplicate.getSQLState());
        }
    }

    @Test
    void upgradesPreviousSchemaWithoutLosingAccounts() throws SQLException {
        Flyway versionOne = Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .cleanDisabled(false)
                .target("1")
                .load();
        assertEquals(1, versionOne.migrate().migrationsExecuted);

        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    INSERT INTO users (id, name, email, password_hash, created_at, active)
                    VALUES ('retained', 'Retained User', 'retained@example.test', 'hash', CURRENT_TIMESTAMP, TRUE)
                    """);
        }

        assertEquals(2, flyway().migrate().migrationsExecuted);
        try (Connection connection = connection(); Statement statement = connection.createStatement();
                var result = statement.executeQuery(
                        "SELECT email, canonical_email FROM users WHERE id = 'retained'")) {
            assertTrue(result.next());
            assertEquals("retained@example.test", result.getString("email"));
            assertEquals("retained@example.test", result.getString("canonical_email"));
        }
    }

    @Test
    void refusesAmbiguousLegacyCanonicalIdentitiesWithoutExposingThem() throws SQLException {
        Flyway versionTwo = Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .cleanDisabled(false)
                .target("2")
                .load();
        versionTwo.migrate();
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    INSERT INTO users (id, name, email, password_hash, created_at, active) VALUES
                    ('case-one', 'First User', 'User@example.test', 'hash', CURRENT_TIMESTAMP, TRUE),
                    ('case-two', 'Second User', 'user@example.test', 'hash', CURRENT_TIMESTAMP, TRUE)
                    """);
        }

        Exception failure = assertThrows(Exception.class, () -> flyway().migrate());

        assertTrue(rootMessage(failure).contains("duplicate identities"));
        assertTrue(!rootMessage(failure).contains("User@example.test"));
    }

    @Test
    void postgresBackupRestoresIntoASeparateDatabase() throws Exception {
        flyway().migrate();
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    INSERT INTO users
                        (id, name, email, canonical_email, password_hash, created_at, active)
                    VALUES
                        ('backup-user', 'Backup User', 'backup@example.test', 'backup@example.test',
                         'hash', CURRENT_TIMESTAMP, TRUE)
                    """);
        }

        assertSuccessful(POSTGRES.execInContainer(
                "pg_dump", "--username", POSTGRES.getUsername(), "--dbname", POSTGRES.getDatabaseName(),
                "--format=custom", "--file=/tmp/authentication.dump"));
        assertSuccessful(POSTGRES.execInContainer(
                "createdb", "--username", POSTGRES.getUsername(), "authentication_restore"));
        assertSuccessful(POSTGRES.execInContainer(
                "pg_restore", "--username", POSTGRES.getUsername(), "--dbname", "authentication_restore",
                "--exit-on-error", "/tmp/authentication.dump"));
        org.testcontainers.containers.Container.ExecResult count = POSTGRES.execInContainer(
                "psql", "--username", POSTGRES.getUsername(), "--dbname", "authentication_restore",
                "--tuples-only", "--no-align", "--command", "SELECT COUNT(*) FROM users;");

        assertSuccessful(count);
        assertEquals("1", count.getStdout().trim());
    }

    private Flyway flyway() {
        return Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .cleanDisabled(false)
                .load();
    }

    private Connection connection() throws SQLException {
        return DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private void assertSuccessful(org.testcontainers.containers.Container.ExecResult result) {
        assertEquals(0, result.getExitCode(), result.getStderr());
    }

    private String rootMessage(Throwable failure) {
        Throwable current = failure;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current.getMessage();
    }
}
