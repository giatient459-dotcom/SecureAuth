package dev.tienday.secureauth.license;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

/** POST {base}/api/v1/verify — base mặc định Netlify. */
public final class OnlineLicenseClient {

    public static final String DEFAULT_API_BASE = "https://secureauth-license.netlify.app";
    public static final String VERIFY_PATH = "/api/v1/verify";

    private OnlineLicenseClient() {}

    public record Result(boolean ok, boolean premium, String reason, String customer, Long expiresAtMs, String raw) {}

    public static Result verify(String apiBase, String apiToken, String key, String hwid,
                                String pluginName, String version, int timeoutMs, Logger log) {
        String base = (apiBase == null || apiBase.isBlank()) ? DEFAULT_API_BASE : apiBase.trim();
        while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        String url = base + VERIFY_PATH;

        HttpURLConnection conn = null;
        try {
            String body = "{"
                    + "\"key\":" + j(key)
                    + ",\"hwid\":" + j(hwid)
                    + ",\"plugin\":" + j(pluginName == null ? "SecureAuth" : pluginName)
                    + ",\"version\":" + j(version == null ? "" : version)
                    + "}";

            conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(Math.max(2000, timeoutMs));
            conn.setReadTimeout(Math.max(2000, timeoutMs));
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            if (apiToken != null && !apiToken.isBlank()) {
                conn.setRequestProperty("Authorization", "Bearer " + apiToken.trim());
            }

            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(bytes.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(bytes);
            }

            int code = conn.getResponseCode();
            InputStream in = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            String resp = in == null ? "" : new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();

            if (resp.isEmpty() || resp.startsWith("<!") || resp.regionMatches(true, 0, "<html", 0, 5)) {
                if (log != null) log.warning("[License] HTTP " + code + " non-JSON from " + url);
                return new Result(false, false, "http_" + code + "_not_json", null, null, resp);
            }

            boolean ok = boolField(resp, "ok");
            boolean premium = boolField(resp, "premium");
            String reason = strField(resp, "reason");
            if (reason == null) reason = ok ? "ok" : "denied";
            String customer = strField(resp, "customer");
            Long exp = longField(resp, "expiresAt");
            return new Result(ok, ok && premium, reason, customer, exp, resp);
        } catch (Exception e) {
            if (log != null) log.warning("[License] Online verify failed: " + e.getMessage());
            return new Result(false, false, "network_error: " + e.getMessage(), null, null, null);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String j(String s) {
        if (s == null) s = "";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }

    private static boolean boolField(String json, String key) {
        String p = "\"" + key + "\"";
        int i = json.indexOf(p);
        if (i < 0) return false;
        int c = json.indexOf(':', i + p.length());
        if (c < 0) return false;
        String rest = json.substring(c + 1).trim();
        return rest.startsWith("true");
    }

    private static String strField(String json, String key) {
        String p = "\"" + key + "\"";
        int i = json.indexOf(p);
        if (i < 0) return null;
        int c = json.indexOf(':', i + p.length());
        if (c < 0) return null;
        int q1 = json.indexOf('"', c + 1);
        if (q1 < 0) return null;
        int q2 = q1 + 1;
        StringBuilder sb = new StringBuilder();
        while (q2 < json.length()) {
            char ch = json.charAt(q2);
            if (ch == '\\' && q2 + 1 < json.length()) {
                sb.append(json.charAt(q2 + 1));
                q2 += 2;
                continue;
            }
            if (ch == '"') break;
            sb.append(ch);
            q2++;
        }
        return sb.toString();
    }

    private static Long longField(String json, String key) {
        String p = "\"" + key + "\"";
        int i = json.indexOf(p);
        if (i < 0) return null;
        int c = json.indexOf(':', i + p.length());
        if (c < 0) return null;
        int j = c + 1;
        while (j < json.length() && Character.isWhitespace(json.charAt(j))) j++;
        if (j < json.length() && json.regionMatches(true, j, "null", 0, 4)) return null;
        int k = j;
        if (k < json.length() && json.charAt(k) == '-') k++;
        while (k < json.length() && Character.isDigit(json.charAt(k))) k++;
        if (k == j || (k == j + 1 && json.charAt(j) == '-')) return null;
        try {
            return Long.parseLong(json.substring(j, k));
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
