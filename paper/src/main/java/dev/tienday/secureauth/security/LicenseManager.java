package dev.tienday.secureauth.security;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import dev.tienday.secureauth.SecureAuthPlugin;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.UUID;
import java.util.logging.Level;

/**
 * License verification with HWID + cache.
 *
 * Luồng:
 *   1. LUÔN tạo HWID trước (kể cả khi key trống)
 *   2. Nếu key trống → unlicensed mode
 *   3. Kiểm tra cache (key|hwid|expiry)
 *   4. Gọi API verify nếu cache hết hạn
 *   5. Lưu cache nếu verify thành công
 *
 * HWID lưu ở plugins/SecureAuth/hwid.txt
 * Cache lưu ở plugins/SecureAuth/license.cache
 */
public class LicenseManager {

    private static final Gson GSON = new Gson();
    private static final String CACHE_FILE = "license.cache";
    private static final long CACHE_TTL_MS = 23 * 60 * 60 * 1000L; // 23 giờ

    private final SecureAuthPlugin plugin;
    private boolean valid = false;
    private String cachedHwid = null;

    public LicenseManager(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    // ── Verify ────────────────────────────────────────────────────────────

    public boolean verify() {
        // ── BƯỚC 1: LUÔN tạo HWID trước ─────────────────────────────────
        String hwid = getHwid();
        plugin.getLogger().info("[License] Server HWID = " + hwid);
        plugin.getLogger().info("[License] Copy HWID này để tạo key trên dashboard");

        // ── BƯỚC 2: Kiểm tra key ────────────────────────────────────────
        String key = plugin.getConfig().getString("license.key", "").trim();
        if (key.isEmpty()) {
            plugin.getLogger().warning("[License] Chưa cấu hình license.key — chạy unlicensed mode.");
            valid = true;
            return true;
        }

        // ── BƯỚC 3: Kiểm tra api-url ────────────────────────────────────
        String apiUrl = plugin.getConfig().getString("license.api-url", "").trim();
        if (apiUrl.isEmpty()) {
            plugin.getLogger().severe("[License] license.api-url not set!");
            return false;
        }

        // ── BƯỚC 4: Kiểm tra cache ──────────────────────────────────────
        if (isCacheValid(key, hwid)) {
            plugin.getLogger().info("[License] Using cached license (valid).");
            valid = true;
            return true;
        }

        // ── BƯỚC 5: Gọi API verify ──────────────────────────────────────
        try {
            JsonObject payload = new JsonObject();
            payload.addProperty("key", key);
            payload.addProperty("hwid", hwid);
            payload.addProperty("plugin", "SecureAuth");
            payload.addProperty("version", plugin.getDescription().getVersion());
            String body = GSON.toJson(payload);

            String cleanUrl = apiUrl.replaceAll("/$", "") + "/v1/verify";
            HttpURLConnection conn = (HttpURLConnection) URI.create(cleanUrl).toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            int status = conn.getResponseCode();
            String resp = readBody(conn);
            conn.disconnect();

            // ── BƯỚC 6: Parse JSON an toàn ──────────────────────────────
            JsonObject json;
            try {
                json = JsonParser.parseString(resp).getAsJsonObject();
            } catch (JsonSyntaxException | IllegalStateException e) {
                plugin.getLogger().severe("[License] Invalid JSON (HTTP " + status + "): " + resp);
                return handleOffline();
            }

            boolean ok = json.has("ok") && json.get("ok").getAsBoolean();
            if (status == 200 && ok) {
                plugin.getLogger().info("[License] License verified.");
                saveCache(key, hwid);
                valid = true;
                return true;
            }

            String reason = json.has("reason") ? json.get("reason").getAsString() : "unknown";
            plugin.getLogger().severe("[License] License invalid: " + reason + " (HTTP " + status + ")");
            return false;

        } catch (Exception e) {
            plugin.getLogger().log(Level.SEVERE, "[License] Cannot reach license server: " + e.getMessage());
            return handleOffline();
        }
    }

    public boolean isValid() { return valid; }

    /** Dùng cho command /authadmin hwid */
    public String getHwidPublic() { return getHwid(); }

    // ── HWID ──────────────────────────────────────────────────────────────

    private String getHwid() {
        if (cachedHwid != null) return cachedHwid;

        File hwidFile = new File(plugin.getDataFolder(), "hwid.txt");

        // Đọc file nếu tồn tại
        if (hwidFile.exists()) {
            try {
                String h = Files.readString(hwidFile.toPath(), StandardCharsets.UTF_8).trim();
                if (!h.isEmpty()) {
                    cachedHwid = h;
                    return cachedHwid;
                }
            } catch (Exception e) {
                plugin.getLogger().warning("[License] Failed to read hwid.txt: " + e.getMessage());
            }
        }

        // Tạo mới
        String generated = "sa-" + UUID.randomUUID();
        try {
            plugin.getDataFolder().mkdirs();
            Files.writeString(hwidFile.toPath(), generated, StandardCharsets.UTF_8);
            plugin.getLogger().info("[License] Created hwid.txt: " + generated);
        } catch (Exception e) {
            plugin.getLogger().warning("[License] Cannot write hwid.txt, using fallback: " + e.getMessage());
            int port = plugin.getServer().getPort();
            String world = plugin.getServer().getWorlds().isEmpty()
                    ? "world" : plugin.getServer().getWorlds().get(0).getName();
            generated = "sa-" + port + "-" + Math.abs(world.hashCode());
        }

        cachedHwid = generated;
        return cachedHwid;
    }

    // ── Cache ─────────────────────────────────────────────────────────────

    private boolean isCacheValid(String key, String hwid) {
        try {
            File f = new File(plugin.getDataFolder(), CACHE_FILE);
            if (!f.exists()) return false;

            String content = Files.readString(f.toPath(), StandardCharsets.UTF_8).trim();
            JsonObject json = JsonParser.parseString(content).getAsJsonObject();

            if (!json.has("key") || !json.get("key").getAsString().equals(key)) return false;
            if (!json.has("hwid") || !json.get("hwid").getAsString().equals(hwid)) return false;
            if (!json.has("expires_at")) return false;

            long expiresAt = json.get("expires_at").getAsLong();
            return System.currentTimeMillis() < expiresAt;

        } catch (Exception e) {
            return false;
        }
    }

    private void saveCache(String key, String hwid) {
        try {
            JsonObject json = new JsonObject();
            json.addProperty("key", key);
            json.addProperty("hwid", hwid);
            json.addProperty("verified_at", System.currentTimeMillis());
            json.addProperty("expires_at", System.currentTimeMillis() + CACHE_TTL_MS);

            File f = new File(plugin.getDataFolder(), CACHE_FILE);
            Files.writeString(f.toPath(), GSON.toJson(json), StandardCharsets.UTF_8);
        } catch (Exception e) {
            plugin.getLogger().warning("[License] Cannot save cache: " + e.getMessage());
        }
    }

    // ── Offline ───────────────────────────────────────────────────────────

    private boolean handleOffline() {
        boolean strict = plugin.getConfig().getBoolean("license.strict", false);
        if (strict) {
            plugin.getLogger().severe("[License] Strict mode ON — plugin disabled.");
            return false;
        }
        plugin.getLogger().warning("[License] Strict mode OFF — starting anyway (offline).");
        valid = true;
        return true;
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static String readBody(HttpURLConnection conn) {
        try {
            InputStream is = conn.getResponseCode() >= 400
                    ? conn.getErrorStream() : conn.getInputStream();
            if (is == null) return "";
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }
}
