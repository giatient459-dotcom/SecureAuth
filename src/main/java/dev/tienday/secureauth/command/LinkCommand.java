package dev.tienday.secureauth.command;

import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.security.RateLimiter;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.logging.Level;

/**
 * /link <code>
 *
 * Gọi HTTP POST /verify-link-code trên Discord bot để xác thực code.
 * Bot lưu code trong RAM Python — plugin không tự lưu trong DB.
 */
public class LinkCommand implements CommandExecutor {

    private static final int MAX_CODE_LEN = 16;

    private final SecureAuthPlugin plugin;

    public LinkCommand(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command,
                             @NotNull String label, @NotNull String[] args) {
        if (!(sender instanceof Player player)) return true;

        UUID playerUuid = player.getUniqueId();

        if (!plugin.getSessionManager().isAuthenticated(playerUuid)) {
            player.sendMessage(plugin.getConfigManager().getMessage("not-logged-in"));
            return true;
        }

        if (args.length < 1) {
            player.sendMessage(plugin.getConfigManager().getMessage("discord-not-linked"));
            return true;
        }

        String code = args[0].replaceAll("[^A-Za-z0-9]", "").toUpperCase();
        if (code.isEmpty() || code.length() > MAX_CODE_LEN) {
            player.sendMessage(plugin.getConfigManager().getMessage("discord-link-invalid"));
            return true;
        }

        RateLimiter rateLimiter = plugin.getRateLimiter();
        String rlKey = "link:" + playerUuid;
        if (!rateLimiter.tryAcquireToken(rlKey,
                plugin.getConfigManager().getLinkAttemptsPer10Min(), 10 * 60_000L)) {
            player.sendMessage(plugin.getConfigManager().getMessage("link-rate-limited"));
            return true;
        }

        String uuidStr    = playerUuid.toString();
        String playerName = player.getName();

        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                // Gọi bot để verify code — bot lưu code trong RAM Python
                BotVerifyResult result = callBotVerify(code, uuidStr);

                if (!result.ok()) {
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (player.isOnline())
                            player.sendMessage(plugin.getConfigManager().getMessage("discord-link-invalid"));
                    });
                    plugin.getLogger().warning("[SecureAuth] Invalid link code by " + playerName
                            + " reason=" + result.reason());
                    plugin.getDatabaseManager().logEvent(uuidStr, playerName, safeIp(player),
                            "LINK_CODE_INVALID", result.reason());
                    return;
                }

                String discordId = result.discordId();
                boolean linked = plugin.getDatabaseManager().setDiscordLink(uuidStr, discordId);

                if (!linked) {
                    plugin.getLogger().warning("[SecureAuth] setDiscordLink failed for " + playerName);
                    return;
                }

                plugin.getLogger().info("[SecureAuth] Discord linked: " + playerName
                        + " ↔ discord_id=****" + discordId.substring(Math.max(0, discordId.length() - 4)));
                plugin.getDatabaseManager().logEvent(uuidStr, playerName, safeIp(player),
                        "LINK_SUCCESS", "Discord linked ok");

                plugin.getServer().getScheduler().runTask(plugin, () -> {
                    if (player.isOnline())
                        player.sendMessage(plugin.getConfigManager().getMessage("discord-link-success"));
                });

            } catch (Throwable t) {
                plugin.getLogger().log(Level.SEVERE, "Link error for " + playerName, t);
            }
        });

        return true;
    }

    // ── HTTP call to bot ──────────────────────────────────────────────────────

    private BotVerifyResult callBotVerify(String code, String mcUuid) {
        String apiUrl    = plugin.getConfigManager().getBotApiUrl();
        String apiSecret = plugin.getConfigManager().getBotApiSecret();
        int    timeout   = plugin.getConfigManager().getBotApiTimeout();

        // Escape JSON values — code và uuid chỉ có alnum + dash nên an toàn
        String body = String.format(
                "{\"code\":\"%s\",\"minecraft_uuid\":\"%s\"}",
                code, mcUuid);

        try {
            HttpURLConnection conn = (HttpURLConnection)
                    URI.create(apiUrl + "/verify-link-code").toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + apiSecret);
            conn.setConnectTimeout(timeout);
            conn.setReadTimeout(timeout);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            int status = conn.getResponseCode();

            if (status == 200) {
                // Đọc discord_id từ response JSON (đơn giản — không cần thư viện JSON)
                String resp = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                String discordId = extractJsonString(resp, "discord_id");
                conn.disconnect();
                if (discordId == null || discordId.isBlank())
                    return BotVerifyResult.fail("missing discord_id in response");
                return BotVerifyResult.ok(discordId);
            }

            // Đọc error reason
            String reason = switch (status) {
                case 404 -> "code not found";
                case 410 -> "code expired";
                case 403 -> "uuid mismatch";
                case 401 -> "bot api auth error";
                default  -> "http " + status;
            };
            conn.disconnect();
            return BotVerifyResult.fail(reason);

        } catch (Exception e) {
            plugin.getLogger().log(Level.WARNING, "Cannot reach Discord bot API: " + e.getMessage());
            return BotVerifyResult.fail("bot unreachable: " + e.getMessage());
        }
    }

    /** Minimal JSON string extractor — tránh thêm dependency */
    private String extractJsonString(String json, String key) {
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

    private static String safeIp(Player player) {
        try {
            if (player.getAddress() != null && player.getAddress().getAddress() != null)
                return player.getAddress().getAddress().getHostAddress();
        } catch (Exception ignored) {}
        return "unknown";
    }

    // ── Result record ─────────────────────────────────────────────────────────

    private record BotVerifyResult(boolean ok, String discordId, String reason) {
        static BotVerifyResult ok(String discordId) {
            return new BotVerifyResult(true, discordId, null);
        }
        static BotVerifyResult fail(String reason) {
            return new BotVerifyResult(false, null, reason);
        }
    }
}
