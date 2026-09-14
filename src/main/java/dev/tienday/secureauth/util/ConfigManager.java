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
     * Called once on enable.
     * FIX: Tự động sửa các giá trị yếu trong config và lưu lại,
     * thay vì chỉ log warning (trước đây file config vẫn giữ giá trị yếu,
     * gây nhầm lẫn cho admin và code khác đọc raw config sẽ thấy sai).
     * Đồng thời kiểm tra HTTPS cho bot API URL.
     */
    public void validate() {
        boolean dirty = false;

        int rawMem = plugin.getConfig().getInt("security.argon2-memory-kb", 65536);
        if (rawMem < ARGON2_MIN_MEMORY_KB) {
            plugin.getLogger().warning("security.argon2-memory-kb (" + rawMem
                    + ") below OWASP minimum " + ARGON2_MIN_MEMORY_KB + " — auto-fixing.");
            plugin.getConfig().set("security.argon2-memory-kb", ARGON2_MIN_MEMORY_KB);
            dirty = true;
        }

        int rawIt = plugin.getConfig().getInt("security.argon2-iterations", 3);
        if (rawIt < ARGON2_MIN_ITERATIONS) {
            plugin.getLogger().warning("security.argon2-iterations (" + rawIt
                    + ") below minimum " + ARGON2_MIN_ITERATIONS + " — auto-fixing.");
            plugin.getConfig().set("security.argon2-iterations", ARGON2_MIN_ITERATIONS);
            dirty = true;
        }

        int rawPar = plugin.getConfig().getInt("security.argon2-parallelism", 4);
        if (rawPar < ARGON2_MIN_PARALLELISM) {
            plugin.getLogger().warning("security.argon2-parallelism (" + rawPar
                    + ") below minimum " + ARGON2_MIN_PARALLELISM + " — auto-fixing.");
            plugin.getConfig().set("security.argon2-parallelism", ARGON2_MIN_PARALLELISM);
            dirty = true;
        }

        // FIX: cảnh báo và ghi log rõ ràng khi secret chưa đổi.
        String secret = getBotApiSecret();
        if (secret == null || secret.isBlank() || "CHANGE_ME_STRONG_SECRET".equals(secret)) {
            plugin.getLogger().log(Level.WARNING,
                    "discord-bot.api-secret has not been changed. 2FA-over-Discord is NOT secure. "
                            + "Generate a random 32+ char secret and set it in config.yml.");
        }

        // FIX: HTTPS validation cho bot API URL.
        // Cho phép localhost (an toàn vì traffic không rời khỏi máy).
        // Mọi host khác bắt buộc phải là https://, nếu không thì API secret
        // có thể bị sniff trên đường truyền.
        String apiUrl = getBotApiUrl();
        if (apiUrl != null && !apiUrl.isBlank()) {
            boolean isLocalhost = apiUrl.startsWith("http://127.0.0.1")
                    || apiUrl.startsWith("http://localhost")
                    || apiUrl.startsWith("http://[::1]")
                    || apiUrl.startsWith("http://0:0:0:0:0:0:0:1");
            boolean isHttps = apiUrl.startsWith("https://");
            if (!isLocalhost && !isHttps) {
                plugin.getLogger().log(Level.SEVERE,
                        "discord-bot.api-url is not HTTPS and not localhost: " + apiUrl
                                + " — API secret may be intercepted. Use https:// in production.");
            }
        }

        if (dirty) {
            plugin.saveConfig();
            plugin.getLogger().info("[ConfigManager] Auto-corrected weak security values and saved config.");
        }
    }

    // ---- Database: SQLite — no config needed, file auto-created ----
    public boolean isDbVerifyServerCertificate() {
        return plugin.getConfig().getBoolean("database.verify-server-certificate", false);
    }

    // ---- Security ----

    public int getSessionTimeout() {
        return Math.max(30, plugin.getConfig().getInt("security.session-timeout", 300));
    }
    public int getMaxLoginAttempts() {
        return Math.max(1, plugin.getConfig().getInt("security.max-login-attempts", 5));
    }
    public int getTwoFaMaxAttempts() {
        return config.getInt("security.two-fa-max-attempts", 3);
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

    // ---- Discord Bot API ----

    public String getBotApiUrl()     { return plugin.getConfig().getString("discord-bot.api-url", "http://127.0.0.1:8765"); }
    public String getBotApiSecret()  { return plugin.getConfig().getString("discord-bot.api-secret", ""); }
    public int    getBotApiTimeout() { return Math.max(500, plugin.getConfig().getInt("discord-bot.api-timeout-ms", 5000)); }

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
