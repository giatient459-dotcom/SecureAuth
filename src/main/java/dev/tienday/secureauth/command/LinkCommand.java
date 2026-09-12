package dev.tienday.secureauth.command;

import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.database.DatabaseManager;
import dev.tienday.secureauth.security.RateLimiter;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;

/**
 * /link <code>
 *
 * The link code carries the Discord user ID (never the Minecraft UUID).
 * The Minecraft UUID is taken from the command sender only.
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

        String code = args[0].replaceAll("[^A-Za-z0-9]", "");
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

        String uuidStr = playerUuid.toString();
        String playerName = player.getName();

        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                DatabaseManager db = plugin.getDatabaseManager();
                Optional<DatabaseManager.LinkConsumeResult> result = db.consumeLinkCode(code);

                if (result.isEmpty()) {
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (player.isOnline()) {
                            player.sendMessage(plugin.getConfigManager().getMessage("discord-link-invalid"));
                        }
                    });
                    plugin.getLogger().warning("[SecureAuth] Invalid link code attempt by " + playerName);
                    db.logEvent(uuidStr, playerName, safeIp(player),
                            "LINK_CODE_INVALID", "Invalid or expired link code");
                    return;
                }

                String discordId = result.get().discordId();

                boolean linked = db.setDiscordLink(uuidStr, discordId);
                if (!linked) {
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (player.isOnline()) {
                            player.sendMessage(plugin.getConfigManager().getMessage("discord-link-invalid"));
                        }
                    });
                    plugin.getLogger().warning("[SecureAuth] setDiscordLink failed for " + playerName);
                    return;
                }

                plugin.getLogger().info("[SecureAuth] Discord linked for " + playerName
                        + " (discord_id=" + redact(discordId) + ")");
                db.logEvent(uuidStr, playerName, safeIp(player),
                        "LINK_SUCCESS", "Discord linked");

                plugin.getServer().getScheduler().runTask(plugin, () -> {
                    if (player.isOnline()) {
                        player.sendMessage(plugin.getConfigManager().getMessage("discord-link-success"));
                    }
                });
            } catch (Throwable t) {
                plugin.getLogger().log(Level.SEVERE, "Link error for " + playerName, t);
            }
        });

        return true;
    }

    private static String redact(String s) {
        if (s == null || s.length() < 5) return "****";
        return "****" + s.substring(s.length() - 4);
    }

    private static String safeIp(Player player) {
        try {
            if (player.getAddress() != null && player.getAddress().getAddress() != null) {
                return player.getAddress().getAddress().getHostAddress();
            }
        } catch (Exception ignored) { }
        return "unknown";
    }
}