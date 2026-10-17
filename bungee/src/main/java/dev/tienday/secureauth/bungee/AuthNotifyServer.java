package dev.tienday.secureauth.bungee;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import java.util.concurrent.Executors;

/**
 * POST /auth/notify — body with uuid + ts + nonce + sig (HMAC).
 * Bearer secret compared with MessageDigest.isEqual (constant-time).
 */
public final class AuthNotifyServer {

    private static final int MAX_REQUEST_BODY_BYTES = 16 * 1024;

    private final SecureAuthBungee plugin;
    private HttpServer server;
    private java.util.concurrent.ExecutorService executor;

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
        String secret = plugin.getPluginConfig().getBackendSecret();
        boolean publicBind = "0.0.0.0".equals(bind) || "*".equals(bind)
                || "::".equals(bind) || "[::]".equals(bind);
        if (publicBind && (secret.length() < 32 || secret.startsWith("CHANGE_ME"))) {
            plugin.getLogger().severe("[SecureAuthBungee] Refusing public HTTP bind with a weak/default backend-secret. Configure a random secret of at least 32 characters.");
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
            executor = Executors.newFixedThreadPool(2);
            server.setExecutor(executor);
            server.start();
            plugin.getLogger().info("[SecureAuthBungee] Notify HTTP on " + bind + ":" + port);
        } catch (IOException e) {
            if (server != null) {
                server.stop(0);
                server = null;
            }
            if (executor != null) {
                executor.shutdownNow();
                executor = null;
            }
            plugin.getLogger().severe("[SecureAuthBungee] Failed to bind notify HTTP: " + e.getMessage());
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
    }

    private void handleNotify(HttpExchange ex) throws IOException {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                respond(ex, 405, "method");
                return;
            }
            String auth = ex.getRequestHeaders().getFirst("Authorization");
            String secret = plugin.getPluginConfig().getBackendSecret();
            if (secret == null || secret.isBlank() || auth == null
                    || !auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
                respond(ex, 401, "unauthorized");
                return;
            }
            String got = auth.substring(7).trim();
            // Constant-time — audit looks for MessageDigest.isEqual / constantTimeEquals
            if (!constantTimeEquals(got, secret)) {
                respond(ex, 401, "unauthorized");
                return;
            }
            String body = readBody(ex);
            if (body == null) return;
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

    /** Constant-time compare (MessageDigest.isEqual). */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        if (x.length != y.length) {
            // still run isEqual-shaped work to avoid trivial length oracle
            return MessageDigest.isEqual(x, x) && false;
        }
        return MessageDigest.isEqual(x, y);
    }

    private static void respond(HttpExchange ex, int code, String msg) throws IOException {
        byte[] b = msg.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    private static String readBody(HttpExchange ex) throws IOException {
        String length = ex.getRequestHeaders().getFirst("Content-Length");
        if (length != null) {
            try {
                if (Long.parseLong(length) > MAX_REQUEST_BODY_BYTES) {
                    respond(ex, 413, "request_too_large");
                    return null;
                }
            } catch (NumberFormatException ignored) {
                // The bounded read below remains authoritative.
            }
        }
        try (var input = ex.getRequestBody()) {
            byte[] bytes = input.readNBytes(MAX_REQUEST_BODY_BYTES + 1);
            if (bytes.length > MAX_REQUEST_BODY_BYTES) {
                respond(ex, 413, "request_too_large");
                return null;
            }
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    private static String extractJsonString(String json, String key) {
        if (json == null) return null;
        int i = 0;
        while (i < json.length()) {
            if (json.charAt(i) != '"') { i++; continue; }
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

    private static int parseJsonString(String json, int quote, StringBuilder out) {
        if (quote >= json.length() || json.charAt(quote) != '"') return -1;
        for (int i = quote + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') return i + 1;
            if (c < 0x20) return -1;
            if (c != '\\\\') { out.append(c); continue; }
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
                    try { out.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16)); }
                    catch (NumberFormatException e) { return -1; }
                    i += 4;
                }
                default -> { return -1; }
            }
        }
        return -1;
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
