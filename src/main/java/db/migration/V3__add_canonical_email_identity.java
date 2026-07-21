package db.migration;

import com.jobseekercopilot.authenticationservice.identity.EmailIdentityCanonicalizer;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.flywaydb.core.api.FlywayException;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

public class V3__add_canonical_email_identity extends BaseJavaMigration {

    @Override
    public void migrate(Context context) throws Exception {
        Connection connection = context.getConnection();
        try (Statement statement = connection.createStatement()) {
            statement.execute("ALTER TABLE users ADD COLUMN canonical_email VARCHAR(254)");
        }

        EmailIdentityCanonicalizer canonicalizer = new EmailIdentityCanonicalizer();
        try (PreparedStatement users = connection.prepareStatement("SELECT id, email FROM users");
                ResultSet result = users.executeQuery();
                PreparedStatement update = connection.prepareStatement(
                        "UPDATE users SET canonical_email = ? WHERE id = ?")) {
            while (result.next()) {
                update.setString(1, canonicalizer.normalize(result.getString("email")).canonical());
                update.setString(2, result.getString("id"));
                update.addBatch();
            }
            update.executeBatch();
        }

        failOnCanonicalCollision(connection);
        try (Statement statement = connection.createStatement()) {
            statement.execute("ALTER TABLE users ALTER COLUMN canonical_email SET NOT NULL");
            statement.execute("ALTER TABLE users ADD CONSTRAINT uk_users_canonical_email UNIQUE (canonical_email)");
        }
    }

    private void failOnCanonicalCollision(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
                ResultSet collision = statement.executeQuery("""
                        SELECT 1
                        FROM users
                        GROUP BY canonical_email
                        HAVING COUNT(*) > 1
                        """)) {
            if (collision.next()) {
                throw new FlywayException(
                        "Canonical email migration found duplicate identities; resolve them before retrying.");
            }
        }
    }
}
