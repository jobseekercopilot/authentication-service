package com.jobseekercopilot.authenticationservice;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
        assertEquals(2, flyway().migrate().migrationsExecuted);

        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    INSERT INTO users (id, name, email, password_hash, created_at, active)
                    VALUES ('first', 'First User', 'first@example.test', 'hash', CURRENT_TIMESTAMP, TRUE)
                    """);

            SQLException duplicate = org.junit.jupiter.api.Assertions.assertThrows(SQLException.class,
                    () -> statement.executeUpdate("""
                            INSERT INTO users (id, name, email, password_hash, created_at, active)
                            VALUES ('second', 'Second User', 'first@example.test', 'hash', CURRENT_TIMESTAMP, TRUE)
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

        assertEquals(1, flyway().migrate().migrationsExecuted);
        try (Connection connection = connection(); Statement statement = connection.createStatement();
                var result = statement.executeQuery("SELECT COUNT(*) FROM users WHERE id = 'retained'")) {
            assertTrue(result.next());
            assertEquals(1, result.getInt(1));
        }
    }

    @Test
    void postgresBackupRestoresIntoASeparateDatabase() throws Exception {
        flyway().migrate();
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    INSERT INTO users (id, name, email, password_hash, created_at, active)
                    VALUES ('backup-user', 'Backup User', 'backup@example.test', 'hash', CURRENT_TIMESTAMP, TRUE)
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
}
