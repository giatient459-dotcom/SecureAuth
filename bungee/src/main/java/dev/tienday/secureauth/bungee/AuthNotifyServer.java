package dev.tienday.secureauth.bungee;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.Executors;

/**
 * POST /auth/notify — body with uuid + ts + nonce + sig (HMAC).
 */
public final class AuthNotifyServer {

    private final SecureAuthBungee plugin;
    private HttpServer server;

    public AuthNotifyServer(SecureAuthBungee plugin) {
        this.plugin = plugin;
    }

    public void start() {
        int port = plugin.getPluginConfig().getHttpPort();
        String bind = plugin.getPluginConfig().getHttpBind();
        if (port <= 0 || port > 65535) {
            plugin.getLogger().warning("[SecureAuthBungee] Invalid http-port — notify disabled.");
            return;
        }
        try {
            server = HttpServer.create(new InetSocketAddress(bind, port), 0);
            server.createContext("/auth/notify", this::handleNotify);
            server.createContext("/auth/health", ex -> {
                byte[] ok = "ok".getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, ok.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(ok);
                }
            });
            server.setExecutor(Executors.newFixedThreadPool(2));
            server.start();
            plugin.getLogger().info("[SecureAuthBungee] Notify HTTP on " + bind + ":" + port);
        } catch (IOException e) {
            plugin.getLogger().severe("[SecureAuthBungee] Failed to bind notify HTTP: " + e.getMessage());
        }
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
    }

    private void handleNotify(HttpExchange ex) throws IOException {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                respond(ex, 405, "method");
                return;
            }
            String auth = ex.getRequestHeaders().getFirst("Authorization");
            String secret = plugin.getPluginConfig().getBackendSecret();
            String expected = "Bearer " + secret;
            if (secret.isBlank() || auth == null || !NotifySigner.constantTimeEq(auth, expected)) {
                respond(ex, 401, "unauthorized");
                return;
            }
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String uuidStr = extractJsonString(body, "uuid");
            String err = NotifySigner.validate(
                    secret, uuidStr,
                    extractTs(body),
                    extractJsonString(body, "nonce"),
                    extractJsonString(body, "sig"),
                    "notify");
            if (err != null) {
                plugin.getLogger().warning("[SecureAuthBungee] notify rejected: " + err);
                respond(ex, 401, err);
                return;
            }
            UUID uuid = UUID.fromString(uuidStr.trim());
            boolean authed = !body.contains("\"authenticated\":false");
            if (authed) {
                plugin.getSessionStore().markAuthenticated(uuid);
                plugin.getLogger().info("[SecureAuthBungee] Auth OK for " + uuid);
            } else {
                plugin.getSessionStore().clear(uuid);
            }
            respond(ex, 200, "ok");
        } catch (Exception e) {
            plugin.getLogger().warning("[SecureAuthBungee] notify error: " + e.getMessage());
            respond(ex, 500, "error");
        }
    }

    private static void respond(HttpExchange ex, int code, String msg) throws IOException {
        byte[] b = msg.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    private static String extractJsonString(String json, String key) {
        if (json == null) return null;
        String needle = "\"" + key + "\"";
        int i = json.indexOf(needle);
        if (i < 0) return null;
        int colon = json.indexOf(':', i + needle.length());
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        int q2 = json.indexOf('"', q1 + 1);
        if (q2 < 0) return null;
        return json.substring(q1 + 1, q2);
    }

    private static String extractTs(String json) {
        String s = extractJsonString(json, "ts");
        if (s != null) return s;
        if (json == null) return null;
        int idx = json.indexOf("\"ts\"");
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx);
        if (colon < 0) return null;
        int i = colon + 1;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        int j = i;
        while (j < json.length() && Character.isDigit(json.charAt(j))) j++;
        return j > i ? json.substring(i, j) : null;
    }
}
