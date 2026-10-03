package dev.tienday.secureauth.security;

import dev.tienday.secureauth.SecureAuthPlugin;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.UUID;
import java.util.logging.Level;

/**
 * Kiểm tra license online khi plugin khởi động.
 *
 * POST <license-url>/v1/verify
 * Body: { "key": "...", "hwid": "<server-id>", "plugin": "SecureAuth", "version": "..." }
 * Response: { "ok": true/false, "reason": "..." }
 *
 * HWID = UUID lưu trong file hwid.txt (tạo 1 lần duy nhất).
 * Cache license lưu trong license.cache (JSON).
 * Nếu verify fail → plugin disable.
 * Nếu không cấu hình key → bỏ qua (dev mode).
 */
public class LicenseManager {

    private static final Gson GSON = new Gson();
    private static final long CACHE_TTL_MS = 24 * 60 * 60 * 1000L; // 24 giờ

    private final SecureAuthPlugin plugin;
    private boolean valid = false;

    public LicenseManager(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    /** Gọi khi onEnable. @return true nếu hợp lệ hoặc không cấu hình key. */
    public boolean verify() {
        String key = plugin.getConfig().getString("license.key", "").trim();
        if (key.isEmpty()) {
            plugin.getLogger().warning("[License] No license key configured — running in unlicensed mode.");
            valid = true;
            return true;
        }

        String apiUrl = plugin.getConfig().getString("license.api-url", "").trim();
        if (apiUrl.isEmpty()) {
            plugin.getLogger().severe("[License] license.api-url not set!");
            return false;
        }

        String hwid = getHwid();
        String ver = plugin.getDescription().getVersion();

        // ── 1. Kiểm tra cache trước ─────────────────────────────────────────
        if (isCacheValid(key, hwid)) {
            plugin.getLogger().info("[License] Using cached license (valid).");
            valid = true;
            return true;
        }

        // ── 2. Gọi API verify ───────────────────────────────────────────────
        try {
            JsonObject payload = new JsonObject();
            payload.addProperty("key", key);
            payload.addProperty("hwid", hwid);
            payload.addProperty("plugin", "SecureAuth");
            payload.addProperty("version", ver);

            String body = GSON.toJson(payload);

            HttpURLConnection conn = (HttpURLConnection)
                    URI.create(apiUrl + "/v1/verify").toURL().openConnection();
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

            // ── 3. Parse JSON an toàn bằng Gson ──────────────────────────────
            JsonObject json;
            try {
                json = JsonParser.parseString(resp).getAsJsonObject();
            } catch (JsonSyntaxException | IllegalStateException e) {
                plugin.getLogger().severe("[License] Invalid JSON response (HTTP " + status + "): " + resp);
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
            plugin.getLogger().log(Level.SEVERE, "[License] Failed to reach license server: " + e.getMessage());
            return handleOffline();
        }
    }

    public boolean isValid() { return valid; }

    // ── HWID: UUID lưu trong file, tạo 1 lần duy nhất ─────────────────────

    private String getHwid() {
        File hwidFile = new File(plugin.getDataFolder(), "hwid.txt");
        try {
            if (hwidFile.exists()) {
                String id = new String(Files.readAllBytes(hwidFile.toPath()), StandardCharsets.UTF_8).trim();
                if (!id.isEmpty()) return id;
            }
            // Tạo mới
            String newId = "sa-" + UUID.randomUUID();
            if (!plugin.getDataFolder().exists()) plugin.getDataFolder().mkdirs();
            Files.write(hwidFile.toPath(), newId.getBytes(StandardCharsets.UTF_8));
            return newId;
        } catch (IOException e) {
            plugin.getLogger().warning("[License] Cannot read/write hwid.txt: " + e.getMessage());
            // Fallback: port + world name (cũ)
            int port = plugin.getServer().getPort();
            String worldName = plugin.getServer().getWorlds().isEmpty()
                    ? "world" : plugin.getServer().getWorlds().get(0).getName();
            return "sa-" + port + "-" + worldName.hashCode();
        }
    }

    // ── Cache license ─────────────────────────────────────────────────────

    private File getCacheFile() {
        return new File(plugin.getDataFolder(), "license.cache");
    }

    private boolean isCacheValid(String key, String hwid) {
        File f = getCacheFile();
        if (!f.exists()) return false;
        try {
            String content = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            JsonObject json = JsonParser.parseString(content).getAsJsonObject();

            if (!json.has("key") || !json.get("key").getAsString().equals(key)) return false;
            if (!json.has("hwid") || !json.get("hwid").getAsString().equals(hwid)) return false;
            if (!json.has("expires_at")) return false;

            long expiresAt = json.get("expires_at").getAsLong();
            if (System.currentTimeMillis() > expiresAt) return false;

            return true;
        } catch (Exception e) {
            plugin.getLogger().warning("[License] Cache corrupted: " + e.getMessage());
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

            if (!plugin.getDataFolder().exists()) plugin.getDataFolder().mkdirs();
            Files.write(getCacheFile().toPath(), GSON.toJson(json).getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            plugin.getLogger().warning("[License] Cannot write cache: " + e.getMessage());
        }
    }

    // ── Offline handling ───────────────────────────────────────────────────

    private boolean handleOffline() {
        boolean strictMode = plugin.getConfig().getBoolean("license.strict", false);
        if (strictMode) return false;
        plugin.getLogger().warning("[License] Strict mode OFF — starting anyway (offline).");
        valid = true;
        return true;
    }

    // ── Helpers ────────────────────────────────────────────────────────────

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
