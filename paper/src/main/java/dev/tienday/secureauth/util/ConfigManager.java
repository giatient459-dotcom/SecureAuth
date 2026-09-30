package dev.tienday.secureauth.util;

import dev.tienday.secureauth.SecureAuthPlugin;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

import java.util.logging.Level;

public class ConfigManager {

    public static final int ARGON2_MIN_MEMORY_KB    = 19 * 1024;
    public static final int ARGON2_MIN_ITERATIONS   = 2;
    public static final int ARGON2_MIN_PARALLELISM  = 1;

    private final SecureAuthPlugin plugin;

    public ConfigManager(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    /**
     * Called once on enable. Warns about weak/missing secrets.
     * Argon2 getters already clamp values, so we check raw config here
     * for logging purposes only.
     */
    public void validate() {
        int rawMem = plugin.getConfig().getInt("security.argon2-memory-kb", 65536);
        int rawIt  = plugin.getConfig().getInt("security.argon2-iterations", 3);
        int rawPar = plugin.getConfig().getInt("security.argon2-parallelism", 4);

        if (rawMem < ARGON2_MIN_MEMORY_KB) {
            plugin.getLogger().warning("security.argon2-memory-kb is below OWASP minimum ("
                    + ARGON2_MIN_MEMORY_KB + "); value will be clamped at runtime.");
        }
        if (rawIt < ARGON2_MIN_ITERATIONS) {
            plugin.getLogger().warning("security.argon2-iterations is below minimum ("
                    + ARGON2_MIN_ITERATIONS + "); value will be clamped at runtime.");
        }
        if (rawPar < ARGON2_MIN_PARALLELISM) {
            plugin.getLogger().warning("security.argon2-parallelism is below minimum ("
                    + ARGON2_MIN_PARALLELISM + "); value will be clamped at runtime.");
        }

        String secret = getBotApiSecret();
        if (secret == null || secret.isBlank() || "CHANGE_ME_STRONG_SECRET".equals(secret)) {
            plugin.getLogger().log(Level.WARNING,
                    "discord-bot.api-secret has not been changed. 2FA-over-Discord is NOT secure.");
        }

    }

    // ---- Database: SQLite — no config needed, file auto-created ----

    // ---- Security ----

    /** Thời gian chờ /login sau khi join (giây) → hết thì kick. */
    public int getLoginTimeout() {
        int v = plugin.getConfig().getInt("security.login-timeout", -1);
        if (v < 0) {
            v = plugin.getConfig().getInt("security.session-timeout", 180);
        }
        return Math.max(30, v);
    }

    /** @deprecated dùng getLoginTimeout() */
    public int getSessionTimeout() {
        return getLoginTimeout();
    }

    /**
     * Idle timeout sau khi đã authenticated (giây).
     * 0 = không kick vì AFK.
     */
    public int getAuthIdleTimeout() {
        return Math.max(0, plugin.getConfig().getInt("security.auth-idle-timeout", 604800));
    }

    /**
     * Vị trí giữ player chưa login (AuthMe-style).
     * null = không tp (giữ chỗ join).
     */
    public org.bukkit.Location getLoginSpawnLocation() {
        String worldName = plugin.getConfig().getString("login-world.world", "");
        if (worldName == null || worldName.isBlank()) {
            worldName = plugin.getConfig().getString("login-world.end-world", "");
        }
        if (worldName == null || worldName.isBlank()) {
            return null;
        }
        org.bukkit.World world = plugin.getServer().getWorld(worldName);
        if (world == null) {
            plugin.getLogger().warning("[SecureAuth] Login spawn world '" + worldName
                    + "' chưa load. Dùng /authsetspawn khi đứng trong world đó, hoặc /mv load.");
            return null;
        }
        double x = plugin.getConfig().getDouble("login-world.x", world.getSpawnLocation().getX());
        double y = plugin.getConfig().getDouble("login-world.y", world.getSpawnLocation().getY());
        double z = plugin.getConfig().getDouble("login-world.z", world.getSpawnLocation().getZ());
        float yaw = (float) plugin.getConfig().getDouble("login-world.yaw", 0);
        float pitch = (float) plugin.getConfig().getDouble("login-world.pitch", 0);
        return new org.bukkit.Location(world, x, y, z, yaw, pitch);
    }

    /** Tên world login spawn (nếu có). */
    public String getLoginSpawnWorldName() {
        String w = plugin.getConfig().getString("login-world.world", "");
        if (w == null || w.isBlank()) {
            w = plugin.getConfig().getString("login-world.end-world", "");
        }
        return w == null ? "" : w;
    }

    public int getMaxAccountsPerIp() {
        return plugin.getConfig().getInt("security.max-accounts-per-ip", 3);
    }
    public int getMaxLoginAttempts() {
        return Math.max(1, plugin.getConfig().getInt("security.max-login-attempts", 5));
    }
    public int getLockoutDuration() {
        return Math.max(1, plugin.getConfig().getInt("security.lockout-duration", 300));
    }
    public int getTwoFaCodeExpiry() {
        return Math.max(30, plugin.getConfig().getInt("security.two-fa-code-expiry", 120));
    }
    public int getTwoFaCodeLength() {
        return Math.min(10, Math.max(4, plugin.getConfig().getInt("security.two-fa-code-length", 6)));
    }
    public int getTwoFaMinResendInterval() {
        return Math.max(0, plugin.getConfig().getInt("security.two-fa-min-resend-interval", 15));
    }
    public int getRegisterAttemptsPer10Min() {
        return Math.max(1, plugin.getConfig().getInt("security.register-attempts-per-10min", 5));
    }
    public int getLinkAttemptsPer10Min() {
        return Math.max(1, plugin.getConfig().getInt("security.link-attempts-per-10min", 10));
    }
    public int getArgon2Iterations() {
        return Math.max(ARGON2_MIN_ITERATIONS, plugin.getConfig().getInt("security.argon2-iterations", 3));
    }
    public int getArgon2MemoryKb() {
        return Math.max(ARGON2_MIN_MEMORY_KB, plugin.getConfig().getInt("security.argon2-memory-kb", 65536));
    }
    public int getArgon2Parallelism() {
        return Math.max(ARGON2_MIN_PARALLELISM, plugin.getConfig().getInt("security.argon2-parallelism", 4));
    }

    // ---- OP Guard ----

    public boolean isOpGuardBlockOpCommands()   { return plugin.getConfig().getBoolean("op-guard.block-op-commands", true); }
    public boolean isOpGuardBlockBypassGrants() { return plugin.getConfig().getBoolean("op-guard.block-bypass-grants", true); }

    // ---- Dangerous Commands ----

    public boolean isDangerousCommandsEnabled() { return plugin.getConfig().getBoolean("dangerous-commands.enabled", true); }
    public java.util.List<String> getDangerousCommandsExtra() {
        return plugin.getConfig().getStringList("dangerous-commands.extra-protected");
    }
    public java.util.List<String> getConsoleOnlyCommands() {
        return plugin.getConfig().getStringList("dangerous-commands.console-only");
    }

    // ---- Velocity Integration ----

    /**
     * URL Velocity HTTP server lắng nghe.
     * Để trống nếu không dùng Velocity.
     * Ví dụ: http://127.0.0.1:20334/auth/notify
     */
    public String getVelocityNotifyUrl() {
        return plugin.getConfig().getString("velocity.notify-url", "");
    }

    public String getBackendSecret() {
        return plugin.getConfig().getString("velocity.backend-secret", "");
    }

    // ---- Discord Bot API ----

    public String getBotApiUrl()     { return plugin.getConfig().getString("discord-bot.api-url", "http://127.0.0.1:8765"); }
    public String getBotApiSecret()  { return plugin.getConfig().getString("discord-bot.api-secret", ""); }
    public int    getBotApiTimeout() { return Math.max(500, plugin.getConfig().getInt("discord-bot.api-timeout-ms", 5000)); }

    // ---- IP session (skip 2FA) ----

    public boolean isIpSessionEnabled() {
        return plugin.getConfig().getBoolean("security.ip-session.enabled", true);
    }
    public int getIpSessionHours() {
        return Math.max(0, plugin.getConfig().getInt("security.ip-session.hours", 72));
    }

    /** true = IP mới gửi Discord nút Xác nhận/Từ chối (không cần /login mã) */
    public boolean isIpConfirmButtonsEnabled() {
        return plugin.getConfig().getBoolean("security.ip-session.confirm-buttons", true);
    }

    public int getIpConfirmExpirySeconds() {
        return Math.max(30, plugin.getConfig().getInt("security.ip-session.confirm-expiry-seconds", 120));
    }

    // ---- Premium auto-login ----

    public boolean isPremiumAutoLogin() {
        return plugin.getConfig().getBoolean("security.premium-auto-login", true);
    }

    /** Premium vẫn bắt 2FA khi IP mới / force2fa */
    public boolean isPremiumRequire2fa() {
        return plugin.getConfig().getBoolean("security.premium-require-2fa", true);
    }

    // ---- Password policy ----

    public boolean isPasswordRequireMixed() {
        return plugin.getConfig().getBoolean("security.password.require-mixed", false);
    }
    public int getPasswordMinLength() {
        return Math.max(6, plugin.getConfig().getInt("security.password.min-length", 8));
    }

    // ---- Register captcha ----

    public boolean isRegisterCaptchaEnabled() {
        return plugin.getConfig().getBoolean("security.register-captcha", false);
    }

    // ---- Grace period after login (ms) ----

    public int getLoginGraceSeconds() {
        return Math.max(0, plugin.getConfig().getInt("security.login-grace-seconds", 3));
    }

    // ---- Backup ----

    public int getBackupIntervalHours() {
        return plugin.getConfig().getInt("backup.interval-hours", 24);
    }
    public int getBackupKeepCount() {
        return Math.max(1, plugin.getConfig().getInt("backup.keep-count", 7));
    }

    // ---- Discord webhook alerts ----

    public boolean isWebhookEnabled() {
        return plugin.getConfig().getBoolean("alerts.webhook-enabled", false);
    }
    public String getWebhookUrl() {
        return plugin.getConfig().getString("alerts.discord-webhook-url", "");
    }

    // ---- Messages ----


    public Component getMessage(String key) {
        String prefix = plugin.getConfig().getString("messages.prefix", "&8[&bSecureAuth&8] ");
        String raw = plugin.getConfig().getString("messages." + key, "&cMessage not found: " + key);
        return LegacyComponentSerializer.legacyAmpersand().deserialize(prefix + raw);
    }

    public Component getMessageNoPrefix(String key) {
        String raw = plugin.getConfig().getString("messages." + key, "Message not found: " + key);
        return LegacyComponentSerializer.legacyAmpersand().deserialize(raw);
    }

    public String getRawMessage(String key) {
        return plugin.getConfig().getString("messages." + key, "");
    }
}
