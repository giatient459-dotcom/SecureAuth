package dev.tienday.secureauth.velocity;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import java.util.concurrent.Executors;

/**
 * POST /auth/notify | /auth/invalidate
 * Body: {"uuid":"...","ts":...,"nonce":"...","sig":"..."}
 * Authorization: Bearer <secret>
 * sig = HMAC-SHA256(secret, uuid|ts|nonce|action)
 */
public final class AuthNotifyServer {

    private final SecureAuthVelocity plugin;
    private HttpServer server;

    public AuthNotifyServer(SecureAuthVelocity plugin) {
        this.plugin = plugin;
    }

    public void start() {
        PluginConfig cfg = plugin.getPluginConfig();
        int port = cfg.getHttpPort();
        String bind = cfg.getHttpBind();
        if (port <= 0 || port > 65535) {
            plugin.getLogger().error("[SecureAuthVelocity] Invalid http-port {}", port);
            return;
        }
        try {
            server = HttpServer.create(new InetSocketAddress(bind, port), 0);
            server.createContext("/auth/notify", this::handleNotify);
            server.createContext("/auth/invalidate", this::handleInvalidate);
            server.createContext("/auth/health", this::handleHealth);
            server.setExecutor(Executors.newFixedThreadPool(2));
            server.start();
            plugin.getLogger().info("[SecureAuthVelocity] Notify HTTP on {}:{}", bind, port);
        } catch (IOException e) {
            plugin.getLogger().error("[SecureAuthVelocity] HTTP bind failed: {}", e.getMessage());
        }
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
    }

    private void handleHealth(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            respond(ex, 405, "{\"error\":\"method\"}");
            return;
        }
        respond(ex, 200, "{\"ok\":true,\"sessions\":" + plugin.getSessionStore().size() + "}");
    }

    private void handleNotify(HttpExchange ex) throws IOException {
        if (!checkMethod(ex, "POST") || !checkAuth(ex)) return;
        String body = readBody(ex);
        String uuidStr = extractJson(body, "uuid");
        String err = NotifySigner.validate(
                plugin.getPluginConfig().getBackendSecret(),
                uuidStr,
                extractJsonNumberOrString(body, "ts"),
                extractJson(body, "nonce"),
                extractJson(body, "sig"),
                "notify");
        if (err != null) {
            plugin.getLogger().warn("[SecureAuthVelocity] notify rejected: {}", err);
            respond(ex, 401, "{\"error\":\"" + err + "\"}");
            return;
        }
        try {
            UUID uuid = UUID.fromString(uuidStr.trim());
            plugin.getSessionStore().markAuthenticated(uuid);
            plugin.getLogger().info("[SecureAuthVelocity] Authenticated {}", uuid);
            respond(ex, 200, "{\"ok\":true}");
        } catch (IllegalArgumentException e) {
            respond(ex, 400, "{\"error\":\"invalid uuid\"}");
        }
    }

    private void handleInvalidate(HttpExchange ex) throws IOException {
        if (!checkMethod(ex, "POST") || !checkAuth(ex)) return;
        String body = readBody(ex);
        String uuidStr = extractJson(body, "uuid");
        String err = NotifySigner.validate(
                plugin.getPluginConfig().getBackendSecret(),
                uuidStr,
                extractJsonNumberOrString(body, "ts"),
                extractJson(body, "nonce"),
                extractJson(body, "sig"),
                "invalidate");
        if (err != null) {
            respond(ex, 401, "{\"error\":\"" + err + "\"}");
            return;
        }
        try {
            UUID uuid = UUID.fromString(uuidStr.trim());
            plugin.getSessionStore().invalidate(uuid);
            respond(ex, 200, "{\"ok\":true}");
        } catch (IllegalArgumentException e) {
            respond(ex, 400, "{\"error\":\"invalid uuid\"}");
        }
    }

    private boolean checkMethod(HttpExchange ex, String method) throws IOException {
        if (method.equalsIgnoreCase(ex.getRequestMethod())) return true;
        respond(ex, 405, "{\"error\":\"method\"}");
        return false;
    }

    private boolean checkAuth(HttpExchange ex) throws IOException {
        String header = ex.getRequestHeaders().getFirst("Authorization");
        String expected = plugin.getPluginConfig().getBackendSecret();
        if (expected == null || expected.isBlank()) {
            respond(ex, 500, "{\"error\":\"secret not configured\"}");
            return false;
        }
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            respond(ex, 401, "{\"error\":\"unauthorized\"}");
            return false;
        }
        String got = header.substring(7).trim();
        if (!constantTimeEquals(got, expected)) {
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
            return MessageDigest.isEqual(x, x) && false;
        }
        return MessageDigest.isEqual(x, y);
    }

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String extractJson(String json, String key) {
        if (json == null) return null;
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        int q2 = json.indexOf('"', q1 + 1);
        if (q2 < 0) return null;
        return json.substring(q1 + 1, q2);
    }

    /** ts may be number without quotes */
    private static String extractJsonNumberOrString(String json, String key) {
        String asStr = extractJson(json, key);
        if (asStr != null) return asStr;
        if (json == null) return null;
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0) return null;
        int i = colon + 1;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        int j = i;
        while (j < json.length() && (Character.isDigit(json.charAt(j)) || json.charAt(j) == '-')) j++;
        if (j > i) return json.substring(i, j);
        return null;
    }
}
