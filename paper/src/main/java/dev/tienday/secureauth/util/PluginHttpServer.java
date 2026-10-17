package dev.tienday.secureauth.util;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.database.PlayerData;
import dev.tienday.secureauth.security.PasswordUtil;
import dev.tienday.secureauth.util.TitleUtil;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
 *   → {"ok":true,"uuid":"...","username":"..."} | 401
 *
 * POST /auth/discord-status
 *   Authorization: Bearer &lt;api-secret&gt;
 *   {"discord_id":"..."}  hoặc  {"uuid":"..."}
 *   → {"linked":bool,"uuid":"...","username":"...","online":bool,"two_fa":bool}
 *
 * GET  /auth/health → {"ok":true}
 */
public final class PluginHttpServer {

    private static final int MAX_REQUEST_BODY_BYTES = 16 * 1024;

    private final SecureAuthPlugin plugin;
    private HttpServer server;
    private java.util.concurrent.ExecutorService executor;

    public PluginHttpServer(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public void start() {
        int port = plugin.getConfig().getInt("discord-bot.plugin-http-port", 20334);
        if (port <= 0 || port > 65535) {
            plugin.getLogger().warning("[PluginHttpServer] Invalid port " + port + " — HTTP disabled.");
            return;
        }

        // 127.0.0.1 = chỉ local (an toàn). 0.0.0.0 = bot remote (cần firewall + secret mạnh).
        String bind = plugin.getConfig().getString("discord-bot.plugin-http-bind", "127.0.0.1");
        if (bind == null || bind.isBlank()) bind = "127.0.0.1";
        bind = bind.trim();
        String apiSecret = plugin.getConfigManager().getBotApiSecret();
        boolean publicBind = "0.0.0.0".equals(bind) || "*".equals(bind)
                || "::".equals(bind) || "[::]".equals(bind);
        if (publicBind && (apiSecret == null || apiSecret.length() < 32
                || apiSecret.startsWith("CHANGE_ME"))) {
            plugin.getLogger().severe("[PluginHttpServer] Refusing public HTTP bind with a weak/default api-secret. Configure a random secret of at least 32 characters.");
            return;
        }

        try {
            server = HttpServer.create(new InetSocketAddress(bind, port), 0);
            server.createContext("/auth/verify-credentials", this::handleVerifyCredentials);
            server.createContext("/auth/discord-status", this::handleDiscordStatus);
            server.createContext("/auth/ip-confirm", this::handleIpConfirm);
            server.createContext("/auth/health", this::handleHealth);
            executor = Executors.newFixedThreadPool(2);
            server.setExecutor(executor);
            server.start();
            plugin.getLogger().info("[PluginHttpServer] Listening on " + bind + ":" + port);
        } catch (Exception e) {
            plugin.getLogger().log(Level.SEVERE, "[PluginHttpServer] Failed to start: " + e.getMessage(), e);
            if (server != null) {
                server.stop(0);
                server = null;
            }
            if (executor != null) {
                executor.shutdownNow();
                executor = null;
            }
        }
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
        plugin.getLogger().info("[PluginHttpServer] Stopped.");
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
        if (body == null) return;
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

        if (opt.isEmpty()) {
            // Constant-time-ish: still run a dummy verify? skip for simplicity, return 401
            respond(ex, 401, "{\"error\":\"invalid_credentials\"}");
            return;
        }

        PlayerData data = opt.get();
        boolean ok = PasswordUtil.verify(password, data.getPasswordHash());
        if (!ok) {
            respond(ex, 401, "{\"error\":\"invalid_credentials\"}");
            return;
        }

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
        if (body == null) return;
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
            // Player lookup must not run off the main thread
            if (Bukkit.isPrimaryThread()) {
                Player p = Bukkit.getPlayer(uuid);
                online = p != null && p.isOnline();
            } else {
                final boolean[] holder = {false};
                final java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(1);
                Bukkit.getScheduler().runTask(plugin, () -> {
                    try {
                        Player p = Bukkit.getPlayer(uuid);
                        holder[0] = p != null && p.isOnline();
                    } finally {
                        latch.countDown();
                    }
                });
                try {
                    latch.await(500, java.util.concurrent.TimeUnit.MILLISECONDS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
                online = holder[0];
            }
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

    /**
     * POST /auth/ip-confirm
     * Body: {"token":"...","action":"approve"|"deny"}
     * Bot gọi khi user bấm nút Xác nhận / Từ chối.
     */
    private void handleIpConfirm(HttpExchange ex) throws IOException {
        if (!checkMethod(ex, "POST")) return;
        if (!checkAuth(ex)) return;

        String body = readBody(ex);
        if (body == null) return;
        String token  = extractJson(body, "token");
        String action = extractJson(body, "action");
        if (token == null || token.isBlank() || action == null || action.isBlank()) {
            respond(ex, 400, "{\"error\":\"missing_token_or_action\"}");
            return;
        }

        var resolved = plugin.getTwoFactorManager().resolveIpConfirm(token, action);
        String uuidStr = resolved.uuid();
        switch (resolved.result()) {
            case APPROVED -> {
                if (uuidStr != null) {
                    try {
                        UUID uuid = UUID.fromString(uuidStr);
                        Bukkit.getScheduler().runTask(plugin, () -> {
                            Player p = Bukkit.getPlayer(uuid);
                            if (p != null && p.isOnline()
                                    && !plugin.getSessionManager().isAuthenticated(uuid)) {
                                new dev.tienday.secureauth.command.LoginCommand(plugin)
                                        .completeLoginFromExternal(p, "ip-confirm-approved");
                            }
                        });
                    } catch (IllegalArgumentException ignored) {}
                }
                respond(ex, 200, "{\"ok\":true,\"result\":\"approved\"}");
            }
            case DENIED -> {
                if (uuidStr != null) {
                    try {
                        UUID uuid = UUID.fromString(uuidStr);
                        Bukkit.getScheduler().runTask(plugin, () -> {
                            Player p = Bukkit.getPlayer(uuid);
                            if (p != null && p.isOnline()) {
                                plugin.getSessionManager().invalidate(uuid);
                                TitleUtil.loginDenied(p);
                                p.kick(plugin.getConfigManager().getMessageNoPrefix("kick-ip-denied"));
                            }
                        });
                    } catch (IllegalArgumentException ignored) {}
                }
                respond(ex, 200, "{\"ok\":true,\"result\":\"denied\"}");
            }
            case EXPIRED -> respond(ex, 410, "{\"error\":\"expired\"}");
            case NOT_FOUND -> respond(ex, 404, "{\"error\":\"not_found\"}");
        }
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
        if (!constantTimeEquals(expected, provided)) {
            respond(ex, 401, "{\"error\":\"unauthorized\"}");
            return false;
        }
        return true;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        if (x.length != y.length) {
            MessageDigest.isEqual(x, x);
            return false;
        }
        return MessageDigest.isEqual(x, y);
    }

    private static String readBody(HttpExchange ex) throws IOException {
        String length = ex.getRequestHeaders().getFirst("Content-Length");
        if (length != null) {
            try {
                if (Long.parseLong(length) > MAX_REQUEST_BODY_BYTES) {
                    respond(ex, 413, "{\"error\":\"request_too_large\"}");
                    return null;
                }
            } catch (NumberFormatException ignored) {
                // Enforce the byte limit while reading even if Content-Length is malformed.
            }
        }
        try (InputStream in = ex.getRequestBody()) {
            byte[] bytes = in.readNBytes(MAX_REQUEST_BODY_BYTES + 1);
            if (bytes.length > MAX_REQUEST_BODY_BYTES) {
                respond(ex, 413, "{\"error\":\"request_too_large\"}");
                return null;
            }
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    /** Extract a top-level JSON string value while honoring JSON escapes. */
    private static String extractJson(String json, String key) {
        if (json == null || json.isBlank()) return null;
        int i = 0;
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c != '"') { i++; continue; }
            StringBuilder token = new StringBuilder();
            int afterToken = parseJsonString(json, i, token);
            if (afterToken < 0) return null;
            int next = afterToken;
            while (next < json.length() && Character.isWhitespace(json.charAt(next))) next++;
            if (next < json.length() && json.charAt(next) == ':') {
                int valueStart = next + 1;
                while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) valueStart++;
                if (!key.equals(token.toString())) {
                    i = valueStart;
                    continue;
                }
                if (valueStart >= json.length() || json.charAt(valueStart) != '"') return null;
                StringBuilder value = new StringBuilder();
                return parseJsonString(json, valueStart, value) < 0 ? null : value.toString();
            }
            i = afterToken;
        }
        return null;
    }

    /** Returns the index after a JSON string, or -1 if it is malformed. */
    private static int parseJsonString(String json, int quote, StringBuilder out) {
        if (quote >= json.length() || json.charAt(quote) != '"') return -1;
        for (int i = quote + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') return i + 1;
            if (c < 0x20) return -1;
            if (c != '\\\\') {
                out.append(c);
                continue;
            }
            if (++i >= json.length()) return -1;
            char escaped = json.charAt(i);
            switch (escaped) {
                case '"', '\\\\', '/' -> out.append(escaped);
                case 'b' -> out.append('\\b');
                case 'f' -> out.append('\\f');
                case 'n' -> out.append('\\n');
                case 'r' -> out.append('\\r');
                case 't' -> out.append('\\t');
                case 'u' -> {
                    if (i + 4 >= json.length()) return -1;
                    try {
                        out.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16));
                    } catch (NumberFormatException e) {
                        return -1;
                    }
                    i += 4;
                }
                default -> { return -1; }
            }
        }
        return -1;
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\", "\\\").replace("\"", "\\"");
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
