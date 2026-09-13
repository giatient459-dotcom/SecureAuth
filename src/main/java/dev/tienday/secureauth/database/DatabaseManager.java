package dev.tienday.secureauth.database;

import dev.tienday.secureauth.SecureAuthPlugin;

import java.io.File;
import java.sql.*;
import java.util.Optional;
import java.util.logging.Level;

/**
 * SQLite-backed DatabaseManager.
 * File: plugins/SecureAuth/secureauth.db
 *
 * Không cần cài MySQL — SQLite là file local, hoạt động trên mọi máy.
 * Tất cả query dùng PreparedStatement, không concatenate string.
 */
public class DatabaseManager {

    private final SecureAuthPlugin plugin;
    private Connection connection;

    public DatabaseManager(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public void init() throws Exception {
        // Đảm bảo thư mục plugin tồn tại
        File dataFolder = plugin.getDataFolder();
        if (!dataFolder.exists()) dataFolder.mkdirs();

        File dbFile = new File(dataFolder, "secureauth.db");
        String url  = "jdbc:sqlite:" + dbFile.getAbsolutePath();

        Class.forName("org.sqlite.JDBC");
        connection = DriverManager.getConnection(url);

        // WAL mode: tăng hiệu năng concurrent read, tránh lock
        try (Statement st = connection.createStatement()) {
            st.execute("PRAGMA journal_mode=WAL");
            st.execute("PRAGMA foreign_keys=ON");
            st.execute("PRAGMA busy_timeout=5000");
        }

        createTables();
        plugin.getLogger().info("SQLite database ready: " + dbFile.getAbsolutePath());
    }

    private void createTables() throws SQLException {
        try (Statement st = connection.createStatement()) {
            st.executeUpdate("""
                CREATE TABLE IF NOT EXISTS sa_players (
                    uuid           TEXT NOT NULL PRIMARY KEY,
                    username       TEXT NOT NULL,
                    password_hash  TEXT NOT NULL,
                    discord_id     TEXT DEFAULT NULL,
                    two_fa_enabled INTEGER DEFAULT 0,
                    registered_at  INTEGER NOT NULL,
                    last_login_at  INTEGER DEFAULT 0,
                    disabled       INTEGER DEFAULT 0
                )
            """);

            st.executeUpdate("""
                CREATE TABLE IF NOT EXISTS sa_link_codes (
                    code        TEXT NOT NULL PRIMARY KEY,
                    uuid        TEXT NOT NULL,
                    discord_id  TEXT NOT NULL,
                    expires_at  INTEGER NOT NULL
                )
            """);

            st.executeUpdate("""
                CREATE TABLE IF NOT EXISTS sa_security_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    uuid        TEXT,
                    username    TEXT,
                    ip_address  TEXT,
                    event_type  TEXT NOT NULL,
                    detail      TEXT,
                    occurred_at INTEGER NOT NULL
                )
            """);

            st.executeUpdate("CREATE INDEX IF NOT EXISTS idx_log_uuid ON sa_security_log(uuid)");
            st.executeUpdate("CREATE INDEX IF NOT EXISTS idx_log_time ON sa_security_log(occurred_at)");
        }
    }

    // ── Reconnect guard ───────────────────────────────────────────────────────

    private Connection getConn() throws SQLException {
        if (connection == null || connection.isClosed()) {
            File dbFile = new File(plugin.getDataFolder(), "secureauth.db");
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbFile.getAbsolutePath());
            try (Statement st = connection.createStatement()) {
                st.execute("PRAGMA journal_mode=WAL");
                st.execute("PRAGMA busy_timeout=5000");
            }
        }
        return connection;
    }

    // ── Player CRUD ───────────────────────────────────────────────────────────

    public Optional<PlayerData> getPlayer(String uuid) {
        final String sql = "SELECT * FROM sa_players WHERE uuid = ? AND disabled = 0 LIMIT 1";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, uuid);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(mapRow(rs));
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "getPlayer error", e);
        }
        return Optional.empty();
    }

    public boolean isRegistered(String uuid) {
        final String sql = "SELECT 1 FROM sa_players WHERE uuid = ? AND disabled = 0 LIMIT 1";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, uuid);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "isRegistered error", e);
        }
        return false;
    }

    public void registerPlayer(String uuid, String username, String passwordHash) {
        final String sql = """
            INSERT OR IGNORE INTO sa_players
                (uuid, username, password_hash, registered_at)
            VALUES (?, ?, ?, ?)
        """;
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, uuid);
            ps.setString(2, username);
            ps.setString(3, passwordHash);
            ps.setLong(4, System.currentTimeMillis());
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "registerPlayer error", e);
        }
    }

    public void updateLastLogin(String uuid) {
        final String sql = "UPDATE sa_players SET last_login_at = ? WHERE uuid = ?";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setLong(1, System.currentTimeMillis());
            ps.setString(2, uuid);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "updateLastLogin error", e);
        }
    }

    public void resetPassword(String uuid, String newHash) {
        final String sql = "UPDATE sa_players SET password_hash = ?, discord_id = NULL, two_fa_enabled = 0 WHERE uuid = ?";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, newHash);
            ps.setString(2, uuid);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "resetPassword error", e);
        }
    }

    public void disableAccount(String uuid) {
        final String sql = "UPDATE sa_players SET disabled = 1 WHERE uuid = ?";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, uuid);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "disableAccount error", e);
        }
    }

    // ── Discord Linking ───────────────────────────────────────────────────────

    public void setDiscordLink(String uuid, String discordId) {
        final String sql = "UPDATE sa_players SET discord_id = ?, two_fa_enabled = 1 WHERE uuid = ?";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, discordId);
            ps.setString(2, uuid);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "setDiscordLink error", e);
        }
    }

    public void clearDiscordLink(String uuid) {
        final String sql = "UPDATE sa_players SET discord_id = NULL, two_fa_enabled = 0 WHERE uuid = ?";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, uuid);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "clearDiscordLink error", e);
        }
    }

    // ── Link Codes ────────────────────────────────────────────────────────────

    public void storeLinkCode(String code, String uuid, String discordId, long expiresAt) {
        final String del = "DELETE FROM sa_link_codes WHERE uuid = ?";
        final String ins = "INSERT OR REPLACE INTO sa_link_codes (code, uuid, discord_id, expires_at) VALUES (?, ?, ?, ?)";
        try {
            Connection conn = getConn();
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement(del)) {
                ps.setString(1, uuid);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = conn.prepareStatement(ins)) {
                ps.setString(1, code);
                ps.setString(2, uuid);
                ps.setString(3, discordId);
                ps.setLong(4, expiresAt);
                ps.executeUpdate();
            }
            conn.commit();
            conn.setAutoCommit(true);
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "storeLinkCode error", e);
            try { connection.rollback(); connection.setAutoCommit(true); } catch (SQLException ignored) {}
        }
    }

    /**
     * Validate code, return discord_id if valid, delete code (one-time use).
     */
    public Optional<String> consumeLinkCode(String code) {
        final String sel = "SELECT uuid, discord_id, expires_at FROM sa_link_codes WHERE code = ? LIMIT 1";
        final String del = "DELETE FROM sa_link_codes WHERE code = ?";
        try {
            Connection conn = getConn();
            conn.setAutoCommit(false);
            String discordId = null;
            try (PreparedStatement ps = conn.prepareStatement(sel)) {
                ps.setString(1, code);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next() && System.currentTimeMillis() <= rs.getLong("expires_at")) {
                        discordId = rs.getString("discord_id");
                    }
                }
            }
            // Always delete — prevent replay even if expired
            try (PreparedStatement ps = conn.prepareStatement(del)) {
                ps.setString(1, code);
                ps.executeUpdate();
            }
            conn.commit();
            conn.setAutoCommit(true);
            return Optional.ofNullable(discordId);
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "consumeLinkCode error", e);
            try { connection.rollback(); connection.setAutoCommit(true); } catch (SQLException ignored) {}
        }
        return Optional.empty();
    }

    // ── Security Log ──────────────────────────────────────────────────────────

    public void logEvent(String uuid, String username, String ip, String eventType, String detail) {
        final String sql = """
            INSERT INTO sa_security_log (uuid, username, ip_address, event_type, detail, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """;
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, uuid);
            ps.setString(2, username);
            ps.setString(3, ip);
            ps.setString(4, eventType);
            ps.setString(5, detail);
            ps.setLong(6, System.currentTimeMillis());
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.WARNING, "logEvent error", e);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private PlayerData mapRow(ResultSet rs) throws SQLException {
        return new PlayerData(
                rs.getString("uuid"),
                rs.getString("username"),
                rs.getString("password_hash"),
                rs.getString("discord_id"),
                rs.getInt("two_fa_enabled") == 1,
                rs.getLong("registered_at"),
                rs.getLong("last_login_at")
        );
    }

    public boolean ready() {
        try { return connection != null && !connection.isClosed(); }
        catch (SQLException e) { return false; }
    }

    public void close() {
        try { if (connection != null && !connection.isClosed()) connection.close(); }
        catch (SQLException e) { plugin.getLogger().log(Level.WARNING, "DB close error", e); }
    }
}
