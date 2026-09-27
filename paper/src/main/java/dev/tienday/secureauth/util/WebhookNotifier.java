package dev.tienday.secureauth.util;

import dev.tienday.secureauth.SecureAuthPlugin;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;

/**
 * Discord webhook alerts (brute-force lockout, admin actions).
 * Runs off main thread — callers must not block.
 */
public final class WebhookNotifier {

    private final SecureAuthPlugin plugin;

    public WebhookNotifier(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public void alertLockout(String username, String uuid, String ip, int attempts) {
        if (!plugin.getConfigManager().isWebhookEnabled()) return;
        String content = String.format(
                "⚠️ **SecureAuth lockout**\nPlayer: `%s`\nUUID: `%s`\nIP: `%s`\nAttempts: **%d**",
                safe(username), safe(uuid), safe(ip), attempts);
        sendAsync(content);
    }

    public void alertAdmin(String action, String admin, String target) {
        if (!plugin.getConfigManager().isWebhookEnabled()) return;
        String content = String.format(
                "🔧 **SecureAuth admin**\nAction: `%s`\nAdmin: `%s`\nTarget: `%s`",
                safe(action), safe(admin), safe(target));
        sendAsync(content);
    }

    private void sendAsync(String content) {
        String url = plugin.getConfigManager().getWebhookUrl();
        if (url == null || url.isBlank()) return;

        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                String body = "{\"content\":" + jsonString(content) + "}";
                HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setConnectTimeout(4000);
                conn.setReadTimeout(4000);
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(body.getBytes(StandardCharsets.UTF_8));
                }
                int code = conn.getResponseCode();
                conn.disconnect();
                if (code < 200 || code >= 300) {
                    plugin.getLogger().warning("[SecureAuth] Webhook HTTP " + code);
                }
            } catch (Exception e) {
                plugin.getLogger().log(Level.WARNING, "[SecureAuth] Webhook failed: " + e.getMessage());
            }
        });
    }

    private static String safe(String s) {
        return s == null ? "?" : s.replace("`", "'");
    }

    private static String jsonString(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }
}
