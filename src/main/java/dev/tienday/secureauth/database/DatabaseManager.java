package dev.tienday.secureauth.database;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.security.PasswordUtil;
import dev.tienday.secureauth.util.ConfigManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.Statement;
import java.util.Optional;
import java.util.logging.Level;

public class DatabaseManager {

    public record LinkConsumeResult(String discordId) { }

    private final SecureAuthPlugin plugin;
    private volatile HikariDataSource dataSource;

    public DatabaseManager(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public void init() throws Exception {
        ConfigManager cfg = plugin.getConfigManager();

        StringBuilder url = new StringBuilder()
                .append("jdbc:mysql://").append(cfg.getDbHost()).append(':').append(cfg.getDbPort())
                .append('/').append(cfg.getDbName())
                .append("?useSSL=").append(cfg.isDbUseSsl())
                .append("&requireSSL=").append(cfg.isDbUseSsl())
                .append("&verifyServerCertificate=").append(cfg.isDbVerifyServerCertificate())
                .append("&serverTimezone=UTC")
                .append("&useUnicode=true&characterEncoding=utf8")
                .append("&cachePrepStmts=true")
                .append("&prepStmtCacheSize=250")
                .append("&prepStmtCacheSqlLimit=2048")
                .append("&useServerPrepStmts=true")
                .append("&rewriteBatchedStatements=true");
        if (!cfg.isDbUseSsl()) {
            url.append("&allowPublicKeyRetrieval=false");
        }

        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(url.toString());
        config.setUsername(cfg.getDbUsername());
        config.setPassword(cfg.getDbPassword());
        config.setMaximumPoolSize(cfg.getDbPoolSize());
        config.setMinimumIdle(Math.min(2, cfg.getDbPoolSize()));
        config.setConnectionTimeout(10_000);
        config.setIdleTimeout(600_000);
        config.setMaxLifetime(1_800_000);
        config.setPoolName("SecureAuth-Pool");
        config.setValidationTimeout(5_000);
        config.setLeakDetectionThreshold(30_000);

        dataSource = new HikariDataSource(config);
        createTables();
        plugin.getLogger().info("Database connection established.");
    }

    private void createTables() throws SQLException {
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS sa_players (
                    uuid          VARCHAR(36)  NOT NULL PRIMARY KEY,
                    username      VARCHAR(16)  NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    discord_id    VARCHAR(32)  DEFAULT NULL,
                    two_fa_enabled TINYINT(1)  DEFAULT 0,
                    registered_at BIGINT       NOT NULL,
                    last_login_at BIGINT       DEFAULT 0,
                    UNIQUE KEY uk_players_discord (discord_id),
                    INDEX idx_players_username (username)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS sa_link_codes (
                    code       VARCHAR(16) NOT NULL PRIMARY KEY,
                    discord_id VARCHAR(32) NOT NULL,
                    expires_at BIGINT      NOT NULL,
                    INDEX idx_link_codes_expires (expires_at),
                    INDEX idx_link_codes_discord (discord_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS sa_security_log (
                    id          BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    uuid        VARCHAR(36),
                    username    VARCHAR(16),
                    ip_address  VARCHAR(45),
                    event_type  VARCHAR(32) NOT NULL,
                    detail      TEXT,
                    occurred_at BIGINT      NOT NULL,
                    INDEX idx_log_uuid (uuid),
                    INDEX idx_log_occurred (occurred_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """);
        }
    }

    private boolean ready() {
        HikariDataSource ds = dataSource;
        return ds != null && !ds.isClosed();
    }

    // ---- Player CRUD ----

    public Optional<PlayerData> getPlayer(String uuid) {
        if (!ready()) return Optional.empty();
        final String sql = "SELECT uuid, username, password_hash, discord_id, two_fa_enabled, "
                + "registered_at, last_login_at FROM sa_players WHERE uuid = ? LIMIT 1";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
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
        if (!ready()) return false;
        final String sql = "SELECT 1 FROM sa_players WHERE uuid = ? LIMIT 1";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
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
        if (!ready()) return false;
        final String sql = "INSERT INTO sa_players (uuid, username, password_hash, registered_at) "
                + "VALUES (?, ?, ?, ?)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, uuid);
            ps.setString(2, username);
            ps.setString(3, passwordHash);
            ps.setLong(4, System.currentTimeMillis());
            ps.executeUpdate();
            return true;
        } catch (SQLIntegrityConstraintViolationException e) {
            return false;
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "registerPlayer error", e);
            return false;
        }
    }

    public void updateLastLogin(String uuid) {
        if (!ready()) return;
        final String sql = "UPDATE sa_players SET last_login_at = ? WHERE uuid = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, System.currentTimeMillis());
            ps.setString(2, uuid);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "updateLastLogin error", e);
        }
    }

    public void disablePassword(String uuid) {
        if (!ready()) return;
        final String sql = "UPDATE sa_players SET password_hash = ?, discord_id = NULL, "
                + "two_fa_enabled = 0 WHERE uuid = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, PasswordUtil.disabledHash());
            ps.setString(2, uuid);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "disablePassword error", e);
        }
    }

    public boolean deletePlayer(String uuid) {
        if (!ready()) return false;
        final String sql = "DELETE FROM sa_players WHERE uuid = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, uuid);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "deletePlayer error", e);
            return false;
        }
    }

    // ---- Discord linking ----

    public boolean setDiscordLink(String uuid, String discordId) {
        if (!ready()) return false;
        final String clearOther = "UPDATE sa_players SET discord_id = NULL, two_fa_enabled = 0 "
                + "WHERE discord_id = ? AND uuid <> ?";
        final String setThis    = "UPDATE sa_players SET discord_id = ?, two_fa_enabled = 1 "
                + "WHERE uuid = ?";

        try (Connection conn = dataSource.getConnection()) {
            boolean prevAuto = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try {
                try (PreparedStatement ps = conn.prepareStatement(clearOther)) {
                    ps.setString(1, discordId);
                    ps.setString(2, uuid);
                    ps.executeUpdate();
                }
                int updated;
                try (PreparedStatement ps = conn.prepareStatement(setThis)) {
                    ps.setString(1, discordId);
                    ps.setString(2, uuid);
                    updated = ps.executeUpdate();
                }
                conn.commit();
                return updated > 0;
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(prevAuto);
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "setDiscordLink error", e);
            return false;
        }
    }

    public void clearDiscordLink(String uuid) {
        if (!ready()) return;
        final String sql = "UPDATE sa_players SET discord_id = NULL, two_fa_enabled = 0 WHERE uuid = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, uuid);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "clearDiscordLink error", e);
        }
    }

    // ---- Link codes ----

    /**
     * Called by the Discord bot. `discordId` is the Discord user ID (not the MC UUID).
     */
    public void storeLinkCode(String code, String discordId, long expiresAt) {
        if (!ready()) return;
        final String del = "DELETE FROM sa_link_codes WHERE discord_id = ? OR expires_at < ?";
        final String ins = "INSERT INTO sa_link_codes (code, discord_id, expires_at) VALUES (?, ?, ?)";

        try (Connection conn = dataSource.getConnection()) {
            boolean prevAuto = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try {
                try (PreparedStatement ps = conn.prepareStatement(del)) {
                    ps.setString(1, discordId);
                    ps.setLong(2, System.currentTimeMillis());
                    ps.executeUpdate();
                }
                try (PreparedStatement ps = conn.prepareStatement(ins)) {
                    ps.setString(1, code);
                    ps.setString(2, discordId);
                    ps.setLong(3, expiresAt);
                    ps.executeUpdate();
                }
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(prevAuto);
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "storeLinkCode error", e);
        }
    }

    /**
     * Atomic consume: SELECT ... FOR UPDATE + DELETE in one transaction.
     */
    public Optional<LinkConsumeResult> consumeLinkCode(String code) {
        if (!ready()) return Optional.empty();
        final String sel = "SELECT discord_id, expires_at FROM sa_link_codes WHERE code = ? FOR UPDATE";
        final String del = "DELETE FROM sa_link_codes WHERE code = ?";

        try (Connection conn = dataSource.getConnection()) {
            boolean prevAuto = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try {
                String discordId = null;
                try (PreparedStatement ps = conn.prepareStatement(sel)) {
                    ps.setString(1, code);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) {
                            long expiresAt = rs.getLong("expires_at");
                            if (System.currentTimeMillis() <= expiresAt) {
                                discordId = rs.getString("discord_id");
                            }
                        }
                    }
                }
                try (PreparedStatement ps = conn.prepareStatement(del)) {
                    ps.setString(1, code);
                    ps.executeUpdate();
                }
                conn.commit();
                return discordId == null
                        ? Optional.empty()
                        : Optional.of(new LinkConsumeResult(discordId));
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(prevAuto);
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "consumeLinkCode error", e);
            return Optional.empty();
        }
    }

    public void deleteAllLinkCodesForDiscord(String discordId) {
        if (!ready()) return;
        final String sql = "DELETE FROM sa_link_codes WHERE discord_id = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, discordId);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.WARNING, "deleteAllLinkCodesForDiscord error", e);
        }
    }

    /**
     * Purges link codes for a minecraft UUID by resolving its linked Discord ID first.
     * sa_link_codes has no minecraft UUID column by design.
     */
    public void deleteAllLinkCodesFor(String minecraftUuid) {
        if (!ready()) return;
        Optional<PlayerData> pd = getPlayer(minecraftUuid);
        if (pd.isEmpty() || pd.get().getDiscordId() == null) return;
        deleteAllLinkCodesForDiscord(pd.get().getDiscordId());
    }

    // ---- Security log ----

    public void logEvent(String uuid, String username, String ip, String eventType, String detail) {
        if (!ready()) return;
        final String sql = "INSERT INTO sa_security_log "
                + "(uuid, username, ip_address, event_type, detail, occurred_at) "
                + "VALUES (?, ?, ?, ?, ?, ?)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
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

    // ---- Helpers ----

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

    public void close() {
        HikariDataSource ds = dataSource;
        if (ds != null && !ds.isClosed()) {
            ds.close();
        }
        dataSource = null;
    }
}