package dev.tienday.secureauth.bungee;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.Executors;

/**
 * HTTP endpoint Paper calls after successful login:
 * POST /auth/notify  Authorization: Bearer <backend-secret>
 * Body: {"uuid":"...","authenticated":true}
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
            if (secret.isBlank() || auth == null || !constantTimeEquals(auth, expected)) {
                respond(ex, 401, "unauthorized");
                return;
            }
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String uuidStr = extractJsonString(body, "uuid");
            if (uuidStr == null || uuidStr.isBlank()) {
                respond(ex, 400, "missing uuid");
                return;
            }
            UUID uuid;
            try {
                uuid = UUID.fromString(uuidStr.trim());
            } catch (IllegalArgumentException e) {
                respond(ex, 400, "bad uuid");
                return;
            }
            boolean authed = body.contains("\"authenticated\":true")
                    || body.contains("\"authenticated\": true");
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

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        if (x.length != y.length) return false;
        int r = 0;
        for (int i = 0; i < x.length; i++) r |= x[i] ^ y[i];
        return r == 0;
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
}
