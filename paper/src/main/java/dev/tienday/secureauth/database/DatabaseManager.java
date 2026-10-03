package dev.tienday.secureauth.database;

import dev.tienday.secureauth.SecureAuthPlugin;

import java.io.File;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;

public class DatabaseManager {

    private static final int SCHEMA_VERSION = 2;

    private final SecureAuthPlugin plugin;
    private volatile Connection connection;

    public DatabaseManager(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    // ── Init ──────────────────────────────────────────────────────────────────

    public synchronized void init() throws Exception {
        // Đóng connection cũ nếu có (tránh leak khi reload)
        closeQuietly();

        File dataFolder = plugin.getDataFolder();
        if (!dataFolder.exists()) dataFolder.mkdirs();

        File nativeDir = new File(dataFolder, "native");
        if (!nativeDir.exists()) nativeDir.mkdirs();
        System.setProperty("org.sqlite.lib.path", nativeDir.getAbsolutePath());
        System.setProperty("org.sqlite.lib.exportPath", nativeDir.getAbsolutePath());

        File dbFile = new File(dataFolder, "secureauth.db");
        String url  = "jdbc:sqlite:" + dbFile.getAbsolutePath();

        Class.forName("org.sqlite.JDBC");
        connection = DriverManager.getConnection(url);

        try (Statement st = connection.createStatement()) {
            st.execute("PRAGMA journal_mode=WAL");
            st.execute("PRAGMA foreign_keys=ON");
            st.execute("PRAGMA busy_timeout=5000");
        }

        createTables();
        runMigrations();

        plugin.getLogger().info("SQLite database ready: " + dbFile.getAbsolutePath()
                + " (schema v" + SCHEMA_VERSION + ")");
    }

    // ── Schema ────────────────────────────────────────────────────────────────

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
                    disabled       INTEGER DEFAULT 0,
                    register_ip    TEXT DEFAULT NULL,
                    last_login_ip  TEXT DEFAULT NULL
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
            st.executeUpdate("""
                CREATE TABLE IF NOT EXISTS sa_schema_version (
                    version    INTEGER PRIMARY KEY,
                    applied_at INTEGER NOT NULL
                )
            """);
        }
    }

    // ── Migration ─────────────────────────────────────────────────────────────

    private void runMigrations() throws SQLException {
        try (Statement st = connection.createStatement()) {
            safeAddColumn(st, "sa_players", "register_ip",
                "ALTER TABLE sa_players ADD COLUMN register_ip TEXT DEFAULT NULL");
            safeAddColumn(st, "sa_players", "last_login_ip",
                "ALTER TABLE sa_players ADD COLUMN last_login_ip TEXT DEFAULT NULL");

            safeCreateIndex(st, "idx_log_uuid",
                "CREATE INDEX IF NOT EXISTS idx_log_uuid ON sa_security_log(uuid)");
            safeCreateIndex(st, "idx_log_time",
                "CREATE INDEX IF NOT EXISTS idx_log_time ON sa_security_log(occurred_at)");
            safeCreateIndex(st, "idx_players_username",
                "CREATE INDEX IF NOT EXISTS idx_players_username ON sa_players(username)");
            safeCreateIndex(st, "idx_players_register_ip",
                "CREATE INDEX IF NOT EXISTS idx_players_register_ip ON sa_players(register_ip)");
            safeCreateIndex(st, "idx_players_last_login_ip",
                "CREATE INDEX IF NOT EXISTS idx_players_last_login_ip ON sa_players(last_login_ip)");
            safeCreateIndex(st, "idx_link_codes_expires",
                "CREATE INDEX IF NOT EXISTS idx_link_codes_expires ON sa_link_codes(expires_at)");
            safeCreateIndex(st, "idx_link_codes_discord",
                "CREATE INDEX IF NOT EXISTS idx_link_codes_discord ON sa_link_codes(discord_id)");

            // Unique partial index — có thể fail nếu DB cũ có duplicate
            safeCreateUniqueIndex(st, "uk_players_discord",
                "CREATE UNIQUE INDEX IF NOT EXISTS uk_players_discord ON sa_players(discord_id) " +
                "WHERE discord_id IS NOT NULL");

            trackSchemaVersion(st);
        }
    }

    private void safeAddColumn(Statement st, String table, String column, String alterSql) {
        try (ResultSet rs = st.executeQuery("PRAGMA table_info(" + table + ")")) {
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) return;
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.WARNING, "[Migration] PRAGMA failed: " + e.getMessage());
            return;
        }
        try {
            st.executeUpdate(alterSql);
            plugin.getLogger().info("[Migration] Added column " + table + "." + column);
        } catch (SQLException e) {
            plugin.getLogger().log(Level.WARNING,
                "[Migration] Skip " + table + "." + column + ": " + e.getMessage());
        }
    }

    private void safeCreateIndex(Statement st, String name, String createSql) {
        try {
            st.executeUpdate(createSql);
        } catch (SQLException e) {
            plugin.getLogger().log(Level.FINE,
                "[Migration] Index " + name + " skip: " + e.getMessage());
        }
    }

    private void safeCreateUniqueIndex(Statement st, String name, String createSql) {
        try {
            st.executeUpdate(createSql);
        } catch (SQLException e) {
            plugin.getLogger().log(Level.WARNING,
                "[Migration] Unique index " + name + " failed (duplicate data?): " + e.getMessage());
        }
    }

    private void trackSchemaVersion(Statement st) {
        try (PreparedStatement ps = connection.prepareStatement(
                "INSERT OR IGNORE INTO sa_schema_version (version, applied_at) VALUES (?, ?)")) {
            ps.setInt(1, SCHEMA_VERSION);
            ps.setLong(2, System.currentTimeMillis());
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.FINE, "[Migration] Schema version skip: " + e.getMessage());
        }
    }

    // ── Connection guard ──────────────────────────────────────────────────────

    private synchronized Connection getConn() throws SQLException {
        if (connection == null || connection.isClosed()) {
            File dbFile = new File(plugin.getDataFolder(), "secureauth.db");
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbFile.getAbsolutePath());
            try (Statement st = connection.createStatement()) {
                st.execute("PRAGMA journal_mode=WAL");
                st.execute("PRAGMA foreign_keys=ON");
                st.execute("PRAGMA busy_timeout=5000");
            }
            plugin.getLogger().warning("[DB] Reconnected to SQLite.");
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

    public Optional<PlayerData> getPlayerIncludingDisabled(String uuid) {
        final String sql = "SELECT * FROM sa_players WHERE uuid = ? LIMIT 1";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setString(1, uuid);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.of(mapRow(rs));
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "getPlayerIncludingDisabled error", e);
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
        final String insertSql = """
            INSERT OR IGNORE INTO sa_players
                (uuid, username, password_hash, registered_at, register_ip, disabled,
                 discord_id, two_fa_enabled, last_login_at)
            VALUES (?, ?, ?, ?, ?, 0, NULL, 0, 0)
            """;
        final String reviveSql = """
            UPDATE sa_players SET
                username = ?, password_hash = ?, registered_at = ?, register_ip = ?,
                disabled = 0, discord_id = NULL, two_fa_enabled = 0, last_login_at = 0
            WHERE uuid = ? AND disabled = 1
            """;
        synchronized (this) {
            Connection conn;
            try { conn = getConn(); } catch (SQLException e) {
                plugin.getLogger().log(Level.SEVERE, "registerPlayer getConn error", e);
                return false;
            }
            try {
                conn.setAutoCommit(false);
                try {
                    try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                        ps.setString(1, uuid);
                        ps.setString(2, username);
                        ps.setString(3, passwordHash);
                        ps.setLong(4, System.currentTimeMillis());
                        ps.setString(5, ip);
                        if (ps.executeUpdate() > 0) {
                            conn.commit();
                            return true;
                        }
                    }
                    try (PreparedStatement ps = conn.prepareStatement(reviveSql)) {
                        ps.setString(1, username);
                        ps.setString(2, passwordHash);
                        ps.setLong(3, System.currentTimeMillis());
                        ps.setString(4, ip);
                        ps.setString(5, uuid);
                        boolean ok = ps.executeUpdate() > 0;
                        conn.commit();
                        return ok;
                    }
                } catch (SQLException e) {
                    try { conn.rollback(); } catch (SQLException ignored) {}
                    throw e;
                } finally {
                    try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
                }
            } catch (SQLException e) {
                plugin.getLogger().log(Level.SEVERE, "registerPlayer error", e);
            }
        }
        return false;
    }

    public void updateLastLogin(String uuid) {
        updateLastLogin(uuid, null);
    }

    public void updateLastLogin(String uuid, String ip) {
        boolean hasIp = ip != null && !ip.isBlank() && !"unknown".equals(ip);
        final String sql = hasIp
                ? "UPDATE sa_players SET last_login_at = ?, last_login_ip = ? WHERE uuid = ?"
                : "UPDATE sa_players SET last_login_at = ? WHERE uuid = ?";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            long now = System.currentTimeMillis();
            if (hasIp) {
                ps.setLong(1, now);
                ps.setString(2, ip);
                ps.setString(3, uuid);
            } else {
                ps.setLong(1, now);
                ps.setString(2, uuid);
            }
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

    public void disablePassword(String uuid) {
        disableAccount(uuid);
    }

    public void deleteAccount(String uuid) {
        final String delCodes  = "DELETE FROM sa_link_codes WHERE uuid = ?";
        final String delPlayer = "DELETE FROM sa_players WHERE uuid = ?";
        synchronized (this) {
            Connection conn;
            try { conn = getConn(); } catch (SQLException e) {
                plugin.getLogger().log(Level.SEVERE, "deleteAccount getConn error", e);
                return;
            }
            try {
                conn.setAutoCommit(false);
                try {
                    try (PreparedStatement ps = conn.prepareStatement(delCodes)) {
                        ps.setString(1, uuid);
                        ps.executeUpdate();
                    }
                    try (PreparedStatement ps = conn.prepareStatement(delPlayer)) {
                        ps.setString(1, uuid);
                        ps.executeUpdate();
                    }
                    conn.commit();
                } catch (SQLException e) {
                    try { conn.rollback(); } catch (SQLException ignored) {}
                    throw e;
                } finally {
                    try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
                }
            } catch (SQLException e) {
                plugin.getLogger().log(Level.SEVERE, "deleteAccount error", e);
            }
        }
    }

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

    public record LinkConsumeResult(String uuid, String discordId) {}

    public void storeLinkCode(String code, String uuid, String discordId, long expiresAt) {
        final String del = "DELETE FROM sa_link_codes WHERE uuid = ?";
        final String ins = "INSERT OR REPLACE INTO sa_link_codes (code, uuid, discord_id, expires_at) VALUES (?, ?, ?, ?)";
        synchronized (this) {
            Connection conn;
            try { conn = getConn(); } catch (SQLException e) {
                plugin.getLogger().log(Level.SEVERE, "storeLinkCode getConn error", e);
                return;
            }
            try {
                conn.setAutoCommit(false);
                try {
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
                } catch (SQLException e) {
                    try { conn.rollback(); } catch (SQLException ignored) {}
                    throw e;
                } finally {
                    try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
                }
            } catch (SQLException e) {
                plugin.getLogger().log(Level.SEVERE, "storeLinkCode error", e);
            }
        }
    }

    public Optional<LinkConsumeResult> consumeLinkCode(String code) {
        final String sel = "SELECT uuid, discord_id, expires_at FROM sa_link_codes WHERE code = ? LIMIT 1";
        final String del = "DELETE FROM sa_link_codes WHERE code = ?";
        synchronized (this) {
            Connection conn;
            try { conn = getConn(); } catch (SQLException e) {
                plugin.getLogger().log(Level.SEVERE, "consumeLinkCode getConn error", e);
                return Optional.empty();
            }
            try {
                conn.setAutoCommit(false);
                LinkConsumeResult result = null;
                try {
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
                    try (PreparedStatement ps = conn.prepareStatement(del)) {
                        ps.setString(1, code);
                        ps.executeUpdate();
                    }
                    conn.commit();
                } catch (SQLException e) {
                    try { conn.rollback(); } catch (SQLException ignored) {}
                    throw e;
                } finally {
                    try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
                }
                return Optional.ofNullable(result);
            } catch (SQLException e) {
                plugin.getLogger().log(Level.SEVERE, "consumeLinkCode error", e);
            }
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

    // ── Admin list / search ───────────────────────────────────────────────────

    public List<PlayerData> listPlayers(int limit) {
        List<PlayerData> out = new ArrayList<>();
        int lim = Math.min(Math.max(limit, 1), 100);
        final String sql = "SELECT * FROM sa_players ORDER BY registered_at DESC LIMIT ?";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            ps.setInt(1, lim);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(mapRow(rs));
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "listPlayers error", e);
        }
        return out;
    }

    public List<PlayerData> searchPlayers(String query) {
        List<PlayerData> out = new ArrayList<>();
        if (query == null || query.isBlank()) return out;
        String q = query.trim();
        final String sql = """
            SELECT * FROM sa_players
            WHERE LOWER(username) LIKE LOWER(?)
               OR uuid LIKE ?
               OR (discord_id IS NOT NULL AND discord_id LIKE ?)
               OR (register_ip IS NOT NULL AND register_ip = ?)
               OR (last_login_ip IS NOT NULL AND last_login_ip = ?)
            LIMIT 50
            """;
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            String like = "%" + q + "%";
            ps.setString(1, like);
            ps.setString(2, like);
            ps.setString(3, like);
            ps.setString(4, q);
            ps.setString(5, q);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(mapRow(rs));
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "searchPlayers error", e);
        }
        return out;
    }

    public List<String> getRecentLogs(String uuidOrNull, int limit) {
        List<String> out = new ArrayList<>();
        int lim = Math.min(Math.max(limit, 1), 50);
        final String sql = uuidOrNull != null
                ? "SELECT occurred_at, event_type, username, ip_address, detail FROM sa_security_log WHERE uuid = ? ORDER BY occurred_at DESC LIMIT ?"
                : "SELECT occurred_at, event_type, username, ip_address, detail FROM sa_security_log ORDER BY occurred_at DESC LIMIT ?";
        try (PreparedStatement ps = getConn().prepareStatement(sql)) {
            if (uuidOrNull != null) {
                ps.setString(1, uuidOrNull);
                ps.setInt(2, lim);
            } else {
                ps.setInt(1, lim);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    out.add(String.format("[%d] %s | %s | %s | %s",
                            rs.getLong("occurred_at"),
                            rs.getString("event_type"),
                            rs.getString("username"),
                            rs.getString("ip_address"),
                            rs.getString("detail")));
                }
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "getRecentLogs error", e);
        }
        return out;
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
        try {
            lastIp = rs.getString("last_login_ip");
            if (rs.wasNull()) lastIp = null;
        } catch (SQLException ignored) {}

        String regIp = null;
        try {
            regIp = rs.getString("register_ip");
            if (rs.wasNull()) regIp = null;
        } catch (SQLException ignored) {}

        boolean disabled = false;
        try { disabled = rs.getInt("disabled") == 1; } catch (SQLException ignored) {}

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

    public synchronized void close() {
        closeQuietly();
    }

    private void closeQuietly() {
        try {
            if (connection != null && !connection.isClosed()) connection.close();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.WARNING, "DB close error", e);
        } finally {
            connection = null;
        }
    }

    public int getSchemaVersion() {
        try (Statement st = getConn().createStatement();
             ResultSet rs = st.executeQuery("SELECT MAX(version) FROM sa_schema_version")) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException ignored) {}
        return 0;
    }
                    }
