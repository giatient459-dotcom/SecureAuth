package dev.tienday.secureauth.license;

import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.logging.Logger;

/**
 * Hybrid license:
 * 1) Online POST https://secureauth-license.netlify.app/api/v1/verify
 * 2) Offline license.key (HMAC local) nếu online fail + còn grace
 * Strict ON → không premium khi fail; Strict OFF → vẫn chạy (offline warn)
 */
public final class LicenseManager {

    public static final String BYPASS_PERM = "secureauth.license.bypass";
    private static final String CACHE_FILE = "license-cache.json";

    private final JavaPlugin plugin;
    private final Logger log;
    private boolean premiumUnlocked;
    private String lastReason = "not checked";
    private String currentHwid;
    private String customer;

    public LicenseManager(JavaPlugin plugin) {
        this.plugin = plugin;
        this.log = plugin.getLogger();
    }

    public void checkOnEnable() {
        currentHwid = HardwareFingerprint.getHwid(plugin);
        log.info("[License] Server HWID = " + currentHwid);
        log.info("[License] Copy HWID này để tạo key trên dashboard");

        if (!plugin.getConfig().getBoolean("license.enabled", true)) {
            premiumUnlocked = true;
            lastReason = "license check disabled";
            log.warning("[License] Check DISABLED — premium unlocked");
            return;
        }

        String key = readLicenseKey();
        boolean online = plugin.getConfig().getBoolean("license.online", true);
        boolean strict = plugin.getConfig().getBoolean("license.strict", false);
        String apiBase = plugin.getConfig().getString("license.api-url", OnlineLicenseClient.DEFAULT_API_BASE);
        if (apiBase == null || apiBase.isBlank()) apiBase = OnlineLicenseClient.DEFAULT_API_BASE;
        String apiToken = plugin.getConfig().getString("license.api-token",
                plugin.getConfig().getString("license.plugin-token", ""));
        int timeout = plugin.getConfig().getInt("license.timeout-ms", 5000);
        int graceDays = plugin.getConfig().getInt("license.offline-grace-days", 7);

        // --- Online first ---
        if (online) {
            if (key.isBlank()) {
                lastReason = "missing license key";
                log.warning("[License] Không có key — đặt license.key hoặc license.key trong config");
            } else {
                String ver = plugin.getDescription().getVersion();
                OnlineLicenseClient.Result r = OnlineLicenseClient.verify(
                        apiBase, apiToken, key, currentHwid, "SecureAuth", ver, timeout, log);
                if (r.ok()) {
                    premiumUnlocked = true;
                    customer = r.customer();
                    lastReason = "online OK — customer=" + (customer != null ? customer : "?");
                    log.info("[License] " + lastReason);
                    saveCache(true, customer, r.expiresAtMs());
                    return;
                }
                lastReason = "online fail: " + r.reason();
                log.warning("[License] Online: " + lastReason);
                if (r.raw() != null && r.raw().length() < 200) {
                    log.warning("[License] Response: " + r.raw());
                }
            }
        }

        // --- Offline local key (optional HMAC) ---
        if (!key.isBlank()) {
            try {
                LicenseValidator.Result local = LicenseValidator.validate(key, currentHwid);
                if (local.ok()) {
                    premiumUnlocked = true;
                    customer = local.payload != null ? local.payload.customer : null;
                    lastReason = "offline HMAC OK";
                    log.info("[License] " + lastReason);
                    saveCache(true, customer, null);
                    return;
                }
            } catch (Throwable t) {
                // offline validator optional
            }
        }

        // --- Grace cache ---
        if (loadCacheValid(graceDays)) {
            premiumUnlocked = true;
            lastReason = "offline grace cache (max " + graceDays + " days)";
            log.warning("[License] Using grace cache — " + lastReason);
            return;
        }

        premiumUnlocked = false;
        if (!strict) {
            log.warning("[License] Strict mode OFF — starting anyway (offline).");
        } else {
            log.warning("[License] Strict mode ON — premium DISABLED.");
        }
        log.warning("[License] HWID (gửi vendor / dán dashboard): " + currentHwid);
    }

    public boolean isPremium() {
        return premiumUnlocked;
    }

    public boolean isPremiumOrBypass(CommandSender sender) {
        if (premiumUnlocked) return true;
        if (sender == null) return false;
        if (sender.hasPermission(BYPASS_PERM)) return true;
        if (!(sender instanceof Player) && sender.isOp()) return true;
        return false;
    }

    public String getLastReason() { return lastReason; }
    public String getCurrentHwid() { return currentHwid; }
    public String getCustomer() { return customer; }

    public void sendInfo(CommandSender sender) {
        sender.sendMessage("§8[§bSecureAuth License§8]");
        sender.sendMessage("§7HWID: §f" + currentHwid);
        sender.sendMessage("§7API: §f" + OnlineLicenseClient.DEFAULT_API_BASE + OnlineLicenseClient.VERIFY_PATH);
        sender.sendMessage("§7Status: " + (premiumUnlocked ? "§aVALID" : "§cINVALID"));
        sender.sendMessage("§7Detail: §f" + lastReason);
        if (customer != null) sender.sendMessage("§7Customer: §f" + customer);
    }

    private String readLicenseKey() {
        String fromCfg = plugin.getConfig().getString("license.key", "");
        if (fromCfg != null && !fromCfg.isBlank()) return fromCfg.trim();
        String name = plugin.getConfig().getString("license.key-file", "license.key");
        Path file = plugin.getDataFolder().toPath().resolve(name == null || name.isBlank() ? "license.key" : name);
        try {
            if (!Files.isRegularFile(file)) return "";
            return Files.readString(file, StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            return "";
        }
    }

    private void saveCache(boolean ok, String cust, Long expMs) {
        try {
            Path p = plugin.getDataFolder().toPath().resolve(CACHE_FILE);
            long now = System.currentTimeMillis();
            String json = "{\"ok\":" + ok
                    + ",\"ts\":" + now
                    + ",\"customer\":" + (cust == null ? "null" : "\"" + cust.replace("\"", "") + "\"")
                    + ",\"expiresAt\":" + (expMs == null ? "null" : expMs)
                    + "}";
            Files.writeString(p, json, StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
    }

    private boolean loadCacheValid(int graceDays) {
        try {
            Path p = plugin.getDataFolder().toPath().resolve(CACHE_FILE);
            if (!Files.isRegularFile(p)) return false;
            String s = Files.readString(p, StandardCharsets.UTF_8);
            if (!s.contains("\"ok\":true")) return false;
            int i = s.indexOf("\"ts\":");
            if (i < 0) return false;
            int j = i + 5;
            while (j < s.length() && Character.isDigit(s.charAt(j))) j++;
            long ts = Long.parseLong(s.substring(i + 5, j));
            long max = graceDays * 86400000L;
            return System.currentTimeMillis() - ts <= max;
        } catch (Exception e) {
            return false;
        }
    }
}
