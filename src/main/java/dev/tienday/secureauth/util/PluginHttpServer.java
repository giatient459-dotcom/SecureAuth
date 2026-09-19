package dev.tienday.secureauth.util;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.database.PlayerData;
import dev.tienday.secureauth.security.PasswordUtil;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.logging.Level;

/**
 * HTTP server nội bộ (127.0.0.1) để Discord bot gọi vào.
 *
 * POST /auth/verify-credentials
 *   Authorization: Bearer &lt;api-secret&gt;
 *   {"username":"...","password":"..."}  hoặc  {"uuid":"...","password":"..."}
 *
 * POST /auth/discord-status
 *   Authorization: Bearer &lt;api-secret&gt;
 *   {"discord_id":"..."}  hoặc  {"uuid":"..."}
 *
 * GET  /auth/health → {"ok":true}
 */
public final class PluginHttpServer {

    private final SecureAuthPlugin plugin;
    private HttpServer server;

    public PluginHttpServer(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public void start() {
        int port = plugin.getConfigManager().getPluginHttpPort();
        if (port <= 0) {
            plugin.getLogger().info("[PluginHttpServer] Disabled (port=0).");
            return;
        }

        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
            server.createContext("/auth/verify-credentials", this::handleVerifyCredentials);
            server.createContext("/auth/discord-status", this::handleDiscordStatus);
            server.createContext("/auth/health", this::handleHealth);
            server.setExecutor(Executors.newFixedThreadPool(2));
            server.start();
            plugin.getLogger().info("[PluginHttpServer] Listening on 127.0.0.1:" + port);
        } catch (BindException e) {
            plugin.getLogger().severe(
                    "[PluginHttpServer] Port " + port + " đang bị chiếm! " +
                    "Đổi discord-bot.plugin-http-port trong config.yml rồi restart.");
            server = null;
        } catch (Exception e) {
            plugin.getLogger().log(Level.SEVERE, "[PluginHttpServer] Failed to start: " + e.getMessage(), e);
            server = null;
        }
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
            plugin.getLogger().info("[PluginHttpServer] Stopped.");
        }
    }

    // ── /auth/health ──────────────────────────────────────────────────────────

    private void handleHealth(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            respond(ex, 405, "{\"error\":\"method_not_allowed\"}");
            return;
        }
        respond(ex, 200, "{\"ok\":true}");
    }

    // ── /auth/verify-credentials ──────────────────────────────────────────────

    private void handleVerifyCredentials(HttpExchange ex) throws IOException {
        if (!checkMethod(ex, "POST")) return;
        if (!checkAuth(ex)) return;

        String body = readBody(ex);
        String username = extractJson(body, "username");
        String uuidStr  = extractJson(body, "uuid");
        String password = extractJson(body, "password");

        if (password == null || password.isBlank()) {
            respond(ex, 400, "{\"error\":\"missing_password\"}");
            return;
        }

        Optional<PlayerData> opt;
        if (uuidStr != null && !uuidStr.isBlank()) {
            opt = plugin.getDatabaseManager().getPlayer(uuidStr);
        } else if (username != null && !username.isBlank()) {
            opt = plugin.getDatabaseManager().getPlayerByUsername(username);
        } else {
            respond(ex, 400, "{\"error\":\"missing_identity\"}");
            return;
        }

        if (opt.isEmpty() || !PasswordUtil.verify(password, opt.get().getPasswordHash())) {
            respond(ex, 401, "{\"error\":\"invalid_credentials\"}");
            return;
        }

        PlayerData data = opt.get();
        String json = String.format(
                "{\"ok\":true,\"uuid\":\"%s\",\"username\":\"%s\"}",
                escape(data.getUuid()), escape(data.getUsername()));
        respond(ex, 200, json);
    }

    // ── /auth/discord-status ──────────────────────────────────────────────────

    private void handleDiscordStatus(HttpExchange ex) throws IOException {
        if (!checkMethod(ex, "POST")) return;
        if (!checkAuth(ex)) return;

        String body = readBody(ex);
        String discordId = extractJson(body, "discord_id");
        String uuidStr   = extractJson(body, "uuid");

        Optional<PlayerData> opt;
        if (discordId != null && !discordId.isBlank()) {
            opt = plugin.getDatabaseManager().getPlayerByDiscordId(discordId);
        } else if (uuidStr != null && !uuidStr.isBlank()) {
            opt = plugin.getDatabaseManager().getPlayer(uuidStr);
        } else {
            respond(ex, 400, "{\"error\":\"missing_identity\"}");
            return;
        }

        if (opt.isEmpty()) {
            respond(ex, 200, "{\"linked\":false,\"online\":false}");
            return;
        }

        PlayerData data = opt.get();
        boolean linked = data.getDiscordId() != null && !data.getDiscordId().isBlank();
        boolean online = false;
        try {
            UUID uuid = UUID.fromString(data.getUuid());
            Player p = Bukkit.getPlayer(uuid);
            online = p != null && p.isOnline();
        } catch (IllegalArgumentException ignored) {}

        String json = String.format(
                "{\"linked\":%b,\"uuid\":\"%s\",\"username\":\"%s\",\"online\":%b,\"two_fa\":%b,\"discord_id\":%s}",
                linked,
                escape(data.getUuid()),
                escape(data.getUsername()),
                online,
                data.isTwoFaEnabled(),
                linked ? "\"" + escape(data.getDiscordId()) + "\"" : "null");
        respond(ex, 200, json);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private boolean checkMethod(HttpExchange ex, String expected) throws IOException {
        if (!expected.equalsIgnoreCase(ex.getRequestMethod())) {
            respond(ex, 405, "{\"error\":\"method_not_allowed\"}");
            return false;
        }
        return true;
    }

    private boolean checkAuth(HttpExchange ex) throws IOException {
        String expected = plugin.getConfigManager().getBotApiSecret();
        if (expected == null || expected.isBlank()) {
            respond(ex, 503, "{\"error\":\"secret_not_configured\"}");
            return false;
        }

        String auth = ex.getRequestHeaders().getFirst("Authorization");
        if (auth == null || !auth.startsWith("Bearer ")) {
            respond(ex, 401, "{\"error\":\"unauthorized\"}");
            return false;
        }

        String provided = auth.substring(7).trim();
        boolean ok = MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                provided.getBytes(StandardCharsets.UTF_8));
        if (!ok) {
            respond(ex, 401, "{\"error\":\"unauthorized\"}");
            return false;
        }
        return true;
    }

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String extractJson(String json, String key) {
        if (json == null || json.isBlank()) return null;
        String pattern = "\"" + key + "\"";
        int idx = json.indexOf(pattern);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + pattern.length());
        if (colon < 0) return null;
        int start = json.indexOf('"', colon + 1);
        if (start < 0) return null;
        int end = json.indexOf('"', start + 1);
        if (end < 0) return null;
        return json.substring(start + 1, end);
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
