package dev.tienday.secureauth.velocity;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class AuthNotifyServer {
    private static final int MAX_REQUEST_BODY_BYTES = 16 * 1024;
    private static final Gson GSON = new Gson();

    private final SecureAuthVelocity plugin;
    private HttpServer server;
    private ExecutorService executor;

    public AuthNotifyServer(SecureAuthVelocity plugin) {
        this.plugin = plugin;
    }

    public synchronized void start() {
        if (server != null) return;
        PluginConfig cfg = plugin.getPluginConfig();
        int port = cfg.getHttpPort();
        String bind = cfg.getHttpBind();
        if (port <= 0 || port > 65535) {
            plugin.getLogger().error("[SecureAuthVelocity] Invalid http-port {}", port);
            return;
        }

        HttpServer newServer = null;
        ExecutorService newExecutor = null;
        try {
            newServer = HttpServer.create(new InetSocketAddress(bind, port), 0);
            newServer.createContext("/auth/notify", this::handleNotify);
            newServer.createContext("/auth/invalidate", this::handleInvalidate);
            newServer.createContext("/auth/health", this::handleHealth);
            newExecutor = Executors.newFixedThreadPool(2);
            newServer.setExecutor(newExecutor);
            newServer.start();
            server = newServer;
            executor = newExecutor;
            plugin.getLogger().info("[SecureAuthVelocity] Notify HTTP on {}:{}", bind, port);
        } catch (IOException | RuntimeException e) {
            if (newServer != null) {
                try {
                    newServer.stop(0);
                } catch (RuntimeException ignored) {
                    // The server may not have reached the started state.
                }
            }
            if (newExecutor != null) newExecutor.shutdownNow();
            plugin.getLogger().error("[SecureAuthVelocity] HTTP bind failed: {}", e.getMessage());
        }
    }

    public synchronized void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    private void handleHealth(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            respond(ex, 405, errorJson("method"));
            return;
        }
        respond(ex, 200, "{\"ok\":true,\"sessions\":" + plugin.getSessionStore().size() + "}");
    }

    private void handleNotify(HttpExchange ex) throws IOException {
        if (!checkMethod(ex, "POST") || !checkAuth(ex)) return;
        JsonObject json = readJsonObject(ex);
        if (json == null) return;

        String uuidStr = getJsonString(json, "uuid");
        String err = NotifySigner.validate(
                plugin.getPluginConfig().getBackendSecret(),
                uuidStr,
                getJsonString(json, "ts"),
                getJsonString(json, "nonce"),
                getJsonString(json, "sig"),
                "notify");
        if (err != null) {
            plugin.getLogger().warn("[SecureAuthVelocity] notify rejected: {}", err);
            respond(ex, 401, errorJson(err));
            return;
        }

        try {
            UUID uuid = UUID.fromString(uuidStr.trim());
            plugin.getSessionStore().markAuthenticated(uuid);
            plugin.getLogger().info("[SecureAuthVelocity] Authenticated {}", uuid);
            respond(ex, 200, "{\"ok\":true}");
        } catch (IllegalArgumentException e) {
            respond(ex, 400, errorJson("invalid uuid"));
        }
    }

    private void handleInvalidate(HttpExchange ex) throws IOException {
        if (!checkMethod(ex, "POST") || !checkAuth(ex)) return;
        JsonObject json = readJsonObject(ex);
        if (json == null) return;

        String uuidStr = getJsonString(json, "uuid");
        String err = NotifySigner.validate(
                plugin.getPluginConfig().getBackendSecret(),
                uuidStr,
                getJsonString(json, "ts"),
                getJsonString(json, "nonce"),
                getJsonString(json, "sig"),
                "invalidate");
        if (err != null) {
            respond(ex, 401, errorJson(err));
            return;
        }

        try {
            UUID uuid = UUID.fromString(uuidStr.trim());
            plugin.getSessionStore().invalidate(uuid);
            respond(ex, 200, "{\"ok\":true}");
        } catch (IllegalArgumentException e) {
            respond(ex, 400, errorJson("invalid uuid"));
        }
    }

    private JsonObject readJsonObject(HttpExchange ex) throws IOException {
        final String body;
        try {
            body = readBody(ex);
        } catch (RequestBodyTooLargeException e) {
            respond(ex, 413, errorJson("request body too large"));
            return null;
        }

        try {
            JsonElement parsed = JsonParser.parseString(body);
            if (parsed == null || !parsed.isJsonObject()) {
                throw new JsonParseException("Expected a JSON object");
            }
            return parsed.getAsJsonObject();
        } catch (JsonParseException | IllegalStateException e) {
            respond(ex, 400, errorJson("invalid json"));
            return null;
        }
    }

    private boolean checkMethod(HttpExchange ex, String method) throws IOException {
        if (method.equalsIgnoreCase(ex.getRequestMethod())) return true;
        respond(ex, 405, errorJson("method"));
        return false;
    }

    private boolean checkAuth(HttpExchange ex) throws IOException {
        String header = ex.getRequestHeaders().getFirst("Authorization");
        String expected = plugin.getPluginConfig().getBackendSecret();
        if (expected == null || expected.isBlank()) {
            respond(ex, 500, errorJson("secret not configured"));
            return false;
        }
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            respond(ex, 401, errorJson("unauthorized"));
            return false;
        }
        if (!constantTimeEquals(header.substring(7).trim(), expected)) {
            respond(ex, 401, errorJson("unauthorized"));
            return false;
        }
        return true;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            String contentLength = ex.getRequestHeaders().getFirst("Content-Length");
            if (contentLength != null) {
                try {
                    if (Long.parseLong(contentLength) > MAX_REQUEST_BODY_BYTES) {
                        throw new RequestBodyTooLargeException();
                    }
                } catch (NumberFormatException ignored) {
                    // The bounded read below remains the authoritative size check.
                }
            }
            byte[] bytes = in.readNBytes(MAX_REQUEST_BODY_BYTES + 1);
            if (bytes.length > MAX_REQUEST_BODY_BYTES) throw new RequestBodyTooLargeException();
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    private static String getJsonString(JsonObject json, String key) {
        JsonElement value = json.get(key);
        if (value == null || value.isJsonNull() || !value.isJsonPrimitive()) return null;
        JsonPrimitive primitive = value.getAsJsonPrimitive();
        if (!primitive.isString() && !primitive.isNumber()) return null;
        return primitive.getAsString();
    }

    private static String errorJson(String code) {
        return GSON.toJson(Map.of("error", code));
    }

    private static void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static final class RequestBodyTooLargeException extends IOException {
        private static final long serialVersionUID = 1L;
    }
}
