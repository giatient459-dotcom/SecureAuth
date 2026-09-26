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

        // Fix: extract native SQLite lib vào thư mục plugin thay vì /tmp
        // Tránh lỗi trên server bị chặn /tmp hoặc CPU arch lạ (arm64 VPS, v.v.)
        File nativeDir = new File(dataFolder, "native");
        if (!nativeDir.exists()) nativeDir.mkdirs();
        System.setProperty("org.sqlite.lib.path", nativeDir.getAbsolutePath());
        System.setProperty("org.sqlite.lib.exportPath", nativeDir.getAbsolutePath());

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
        // Safe migrations for existing DBs
        try (Statement st = connection.createStatement()) {
            try { st.executeUpdate("ALTER TABLE sa_players ADD COLUMN register_ip TEXT DEFAULT NULL"); }
            catch (SQLException ignored) {}
            try { st.executeUpdate("ALTER TABLE sa_players ADD COLUMN last_login_ip TEXT DEFAULT NULL"); }
            catch (SQLException ignored) {}
        }
    }

    // ── Reconnect guard ───────────────────────────────────────────────────────

    private Connection getConn() throws SQLException {
        if (connection == null || connection.isClosed()) {
            File dbFile = new File(plugin.getDataFolder(), "secureauth.db");
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbFile.getAbsolutePath());
            try (Statement st = connection.createStatement()) {
                st.execute("PRAGMA journal_mode=WAL");
                st.execute("PRAGMA foreign_keys=ON");
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

    public boolean registerPlayer(String uuid, String username, String passwordHash) {
        return registerPlayer(uuid, username, passwordHash, null);
    }

    public boolean registerPlayer(String uuid, String username, String passwordHash, String ip) {
        final String sql = """
            INSERT OR IGNORE INTO sa_players
                (uuid, username, password_hash, registered_at, register_ip)
            VALUES (?, ?, ?, ?, ?)
            """;
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, uuid);
            ps.setString(2, username);
            ps.setString(3, passwordHash);
            ps.setLong(4, System.currentTimeMillis());
            ps.setString(5, ip);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "registerPlayer error", e);
        }
        return false;
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

    /** Player /changepassword — keep Discord link and 2FA flag. */
    public void resetPasswordKeepLink(String uuid, String newHash) {
        final String sql = "UPDATE sa_players SET password_hash = ? WHERE uuid = ?";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, newHash);
            ps.setString(2, uuid);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "resetPasswordKeepLink error", e);
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

    /** Alias used by AuthAdminCommand — marks account as disabled */
    public void disablePassword(String uuid) {
        disableAccount(uuid);
    }

    /** Delete all pending link codes for a UUID (used on reset/resetfa) */
    public void deleteAllLinkCodesFor(String uuid) {
        final String sql = "DELETE FROM sa_link_codes WHERE uuid = ?";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, uuid);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "deleteAllLinkCodesFor error", e);
        }
    }

    public Optional<PlayerData> getPlayerByUsername(String username) {
        final String sql = "SELECT * FROM sa_players WHERE LOWER(username) = LOWER(?) AND disabled = 0 LIMIT 1";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(mapRow(rs));
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "getPlayerByUsername error", e);
        }
        return Optional.empty();
    }

    public Optional<PlayerData> getPlayerByDiscordId(String discordId) {
        final String sql = "SELECT * FROM sa_players WHERE discord_id = ? AND disabled = 0 LIMIT 1";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, discordId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(mapRow(rs));
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "getPlayerByDiscordId error", e);
        }
        return Optional.empty();
    }

    // ── Discord Linking ───────────────────────────────────────────────────────

    public boolean setDiscordLink(String uuid, String discordId) {
        final String sql = "UPDATE sa_players SET discord_id = ?, two_fa_enabled = 1 WHERE uuid = ?";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, discordId);
            ps.setString(2, uuid);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "setDiscordLink error", e);
        }
        return false;
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

    /** Result of consuming a link code — carries both uuid and discordId */
    public record LinkConsumeResult(String uuid, String discordId) {}

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
     * Validate code, return LinkConsumeResult if valid, delete code (one-time use).
     */
    public Optional<LinkConsumeResult> consumeLinkCode(String code) {
        final String sel = "SELECT uuid, discord_id, expires_at FROM sa_link_codes WHERE code = ? LIMIT 1";
        final String del = "DELETE FROM sa_link_codes WHERE code = ?";
        try {
            Connection conn = getConn();
            conn.setAutoCommit(false);
            LinkConsumeResult result = null;
            try (PreparedStatement ps = conn.prepareStatement(sel)) {
                ps.setString(1, code);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next() && System.currentTimeMillis() <= rs.getLong("expires_at")) {
                        result = new LinkConsumeResult(
                                rs.getString("uuid"),
                                rs.getString("discord_id")
                        );
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
            return Optional.ofNullable(result);
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "consumeLinkCode error", e);
            try { connection.rollback(); connection.setAutoCommit(true); } catch (SQLException ignored) {}
        }
        return Optional.empty();
    }

    // ── IP limit ──────────────────────────────────────────────────────────────

    public int countAccountsByIp(String ip) {
        if (ip == null || ip.isBlank() || "unknown".equals(ip)) return 0;
        final String sql = "SELECT COUNT(*) FROM sa_players WHERE register_ip = ? AND disabled = 0";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, ip);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.WARNING, "countAccountsByIp error", e);
        }
        return 0;
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
        String discord = rs.getString("discord_id");
        if (rs.wasNull()) discord = null;
        String lastIp = null;
        String regIp = null;
        try {
            lastIp = rs.getString("last_login_ip");
            if (rs.wasNull()) lastIp = null;
        } catch (SQLException ignored) {}
        try {
            regIp = rs.getString("register_ip");
            if (rs.wasNull()) regIp = null;
        } catch (SQLException ignored) {}
        boolean disabled = false;
        try {
            disabled = rs.getInt("disabled") == 1;
        } catch (SQLException ignored) {}
        return new PlayerData(
                rs.getString("uuid"),
                rs.getString("username"),
                rs.getString("password_hash"),
                discord,
                rs.getInt("two_fa_enabled") == 1,
                rs.getLong("registered_at"),
                rs.getLong("last_login_at"),
                disabled,
                lastIp,
                regIp
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
