package dev.tienday.secureauth.command;

import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.database.PlayerData;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;

public class AuthAdminCommand implements CommandExecutor {

    private final SecureAuthPlugin plugin;

    public AuthAdminCommand(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command,
                             @NotNull String label, @NotNull String[] args) {

        if (!sender.hasPermission("secureauth.admin")) {
            sender.sendMessage(Component.text("No permission.", NamedTextColor.RED));
            return true;
        }

        if (args.length < 1) {
            sendUsage(sender);
            return true;
        }

        String sub = args[0].toLowerCase();
        switch (sub) {
            case "reset" -> {
                if (args.length < 2) { sendUsage(sender); return true; }
                handlePlayerSub(sender, args[1], this::handleReset);
            }
            case "resetfa" -> {
                if (args.length < 2) { sendUsage(sender); return true; }
                handlePlayerSub(sender, args[1], this::handleResetTwoFa);
            }
            case "info" -> {
                if (args.length < 2) { sendUsage(sender); return true; }
                handlePlayerSub(sender, args[1], this::handleInfo);
            }
            case "list" -> handleList(sender, args);
            case "search" -> {
                if (args.length < 2) {
                    sender.sendMessage(Component.text("Usage: /authadmin search <name|uuid|ip|discord>", NamedTextColor.YELLOW));
                    return true;
                }
                handleSearch(sender, args[1]);
            }
            case "logs" -> handleLogs(sender, args);
            case "backup" -> handleBackup(sender);
            default -> sendUsage(sender);
        }
        return true;
    }

    private void sendUsage(CommandSender sender) {
        sender.sendMessage(Component.text(
                "Usage: /authadmin <reset|resetfa|info|list|search|logs|backup> ...", NamedTextColor.YELLOW));
    }

    @FunctionalInterface
    private interface PlayerHandler {
        void handle(CommandSender sender, OfflinePlayer target, UUID targetUuid, String uuid);
    }

    private void handlePlayerSub(CommandSender sender, String targetName, PlayerHandler handler) {
        if (!targetName.matches("[A-Za-z0-9_]{3,16}")) {
            sender.sendMessage(Component.text("Invalid player name.", NamedTextColor.RED));
            return;
        }
        OfflinePlayer target = resolvePlayer(targetName);
        if (target == null || target.getUniqueId() == null) {
            sender.sendMessage(Component.text("Player not found.", NamedTextColor.RED));
            return;
        }
        UUID targetUuid = target.getUniqueId();
        handler.handle(sender, target, targetUuid, targetUuid.toString());
    }

    @SuppressWarnings("deprecation")
    private OfflinePlayer resolvePlayer(String name) {
        Player online = plugin.getServer().getPlayerExact(name);
        if (online != null) return online;
        OfflinePlayer offline = plugin.getServer().getOfflinePlayer(name);
        if (offline != null && (offline.hasPlayedBefore() || offline.isOnline())
                && offline.getUniqueId() != null) {
            return offline;
        }
        return null;
    }

    private void handleReset(CommandSender sender, OfflinePlayer target,
                             UUID targetUuid, String uuid) {
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                plugin.getDatabaseManager().deleteAccount(uuid);
                plugin.getTwoFactorManager().clearCode(uuid);
                plugin.getRateLimiter().clearFailures(uuid);
                plugin.getRateLimiter().clearTokens("register:" + uuid);
                plugin.getRateLimiter().clearTokens("link:" + uuid);
                if (plugin.getIpSessionStore() != null) plugin.getIpSessionStore().clear(uuid);

                plugin.getDatabaseManager().logEvent(uuid, target.getName(), "admin",
                        "ADMIN_RESET", "Account deleted by " + sender.getName() + " — can re-register");
                if (plugin.getWebhookNotifier() != null) {
                    plugin.getWebhookNotifier().alertAdmin("reset", sender.getName(), target.getName());
                }

                plugin.getServer().getScheduler().runTask(plugin, () -> {
                    Player online = plugin.getServer().getPlayer(targetUuid);
                    if (online != null) {
                        plugin.getSessionManager().invalidate(targetUuid);
                        online.kick(Component.text("Your account has been reset by an admin. Please /register again."));
                    }
                    sender.sendMessage(Component.text(
                            "Account deleted for " + target.getName() + ". They can /register again.",
                            NamedTextColor.GREEN));
                });
            } catch (Throwable t) {
                plugin.getLogger().log(Level.SEVERE, "Admin reset failed", t);
                plugin.getServer().getScheduler().runTask(plugin, () ->
                        sender.sendMessage(Component.text(
                                "Reset failed — check server console.", NamedTextColor.RED)));
            }
        });
    }

    private void handleResetTwoFa(CommandSender sender, OfflinePlayer target, UUID targetUuid, String uuid) {
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                plugin.getDatabaseManager().deleteAllLinkCodesFor(uuid);
                plugin.getDatabaseManager().clearDiscordLink(uuid);
                plugin.getTwoFactorManager().clearCode(uuid);
                if (plugin.getIpSessionStore() != null) plugin.getIpSessionStore().clear(uuid);

                plugin.getDatabaseManager().logEvent(uuid, target.getName(), "admin",
                        "ADMIN_RESETFA", "2FA cleared by " + sender.getName());
                if (plugin.getWebhookNotifier() != null) {
                    plugin.getWebhookNotifier().alertAdmin("resetfa", sender.getName(), target.getName());
                }

                plugin.getServer().getScheduler().runTask(plugin, () -> {
                    Player online = plugin.getServer().getPlayer(targetUuid);
                    if (online != null) {
                        plugin.getSessionManager().invalidate(targetUuid);
                    }
                    sender.sendMessage(Component.text(
                            "2FA / Discord link cleared for " + target.getName() + ".", NamedTextColor.GREEN));
                });
            } catch (Throwable t) {
                plugin.getLogger().log(Level.SEVERE, "Admin resetfa failed", t);
                plugin.getServer().getScheduler().runTask(plugin, () ->
                        sender.sendMessage(Component.text(
                                "Reset failed — check server console.", NamedTextColor.RED)));
            }
        });
    }

    private void handleInfo(CommandSender sender, OfflinePlayer target,
                            UUID targetUuid, String uuid) {
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                Optional<PlayerData> dataOpt = plugin.getDatabaseManager().getPlayerIncludingDisabled(uuid);
                boolean authed = plugin.getSessionManager().isAuthenticated(targetUuid);
                int fails = plugin.getRateLimiter().getFailureCount(uuid);

                plugin.getServer().getScheduler().runTask(plugin, () -> {
                    if (dataOpt.isEmpty()) {
                        sender.sendMessage(Component.text(
                                target.getName() + " is not registered.", NamedTextColor.YELLOW));
                        return;
                    }
                    PlayerData d = dataOpt.get();
                    sender.sendMessage(Component.text(
                            "── SecureAuth Info: " + d.getUsername() + " ──", NamedTextColor.AQUA));
                    sender.sendMessage(Component.text("UUID: " + d.getUuid(), NamedTextColor.GRAY));
                    sender.sendMessage(Component.text(
                            "Disabled: " + d.isDisabled(), NamedTextColor.GRAY));
                    sender.sendMessage(Component.text(
                            "Discord: " + (d.getDiscordId() != null ? redact(d.getDiscordId()) : "not linked"),
                            NamedTextColor.GRAY));
                    sender.sendMessage(Component.text(
                            "2FA enabled: " + d.isTwoFaEnabled(), NamedTextColor.GRAY));
                    sender.sendMessage(Component.text(
                            "Last IP: " + (d.getLastLoginIp() != null ? d.getLastLoginIp() : "n/a"),
                            NamedTextColor.GRAY));
                    sender.sendMessage(Component.text(
                            "Register IP: " + (d.getRegisterIp() != null ? d.getRegisterIp() : "n/a"),
                            NamedTextColor.GRAY));
                    sender.sendMessage(Component.text(
                            "Session active: " + authed, NamedTextColor.GRAY));
                    sender.sendMessage(Component.text(
                            "Fail attempts: " + fails, NamedTextColor.GRAY));
                });
            } catch (Throwable t) {
                plugin.getLogger().log(Level.SEVERE, "Admin info failed", t);
            }
        });
    }

    private void handleList(CommandSender sender, String[] args) {
        int limit = 20;
        if (args.length >= 2) {
            try { limit = Integer.parseInt(args[1]); } catch (NumberFormatException ignored) {}
        }
        final int lim = limit;
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            List<PlayerData> list = plugin.getDatabaseManager().listPlayers(lim);
            plugin.getServer().getScheduler().runTask(plugin, () -> {
                sender.sendMessage(Component.text("── Accounts (newest " + list.size() + ") ──", NamedTextColor.AQUA));
                for (PlayerData d : list) {
                    sender.sendMessage(Component.text(
                            d.getUsername() + " | " + (d.isDisabled() ? "DISABLED" : "ok")
                                    + " | 2FA=" + d.isTwoFaEnabled()
                                    + " | ip=" + (d.getLastLoginIp() != null ? d.getLastLoginIp() : "-"),
                            NamedTextColor.GRAY));
                }
            });
        });
    }

    private void handleSearch(CommandSender sender, String query) {
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            List<PlayerData> list = plugin.getDatabaseManager().searchPlayers(query);
            plugin.getServer().getScheduler().runTask(plugin, () -> {
                if (list.isEmpty()) {
                    sender.sendMessage(Component.text("No matches for: " + query, NamedTextColor.YELLOW));
                    return;
                }
                sender.sendMessage(Component.text("── Search: " + list.size() + " result(s) ──", NamedTextColor.AQUA));
                for (PlayerData d : list) {
                    sender.sendMessage(Component.text(
                            d.getUsername() + " | uuid=" + d.getUuid().substring(0, 8) + "…"
                                    + " | discord=" + (d.getDiscordId() != null ? redact(d.getDiscordId()) : "-")
                                    + " | lastIp=" + (d.getLastLoginIp() != null ? d.getLastLoginIp() : "-"),
                            NamedTextColor.GRAY));
                }
            });
        });
    }

    private void handleLogs(CommandSender sender, String[] args) {
        final String playerName = args.length >= 2 ? args[1] : null;
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            String uuid = null;
            if (playerName != null) {
                OfflinePlayer t = resolvePlayer(playerName);
                if (t != null && t.getUniqueId() != null) uuid = t.getUniqueId().toString();
            }
            List<String> logs = plugin.getDatabaseManager().getRecentLogs(uuid, 20);
            plugin.getServer().getScheduler().runTask(plugin, () -> {
                sender.sendMessage(Component.text("── Recent logs ──", NamedTextColor.AQUA));
                if (logs.isEmpty()) {
                    sender.sendMessage(Component.text("(empty)", NamedTextColor.GRAY));
                    return;
                }
                for (String line : logs) {
                    sender.sendMessage(Component.text(line, NamedTextColor.GRAY));
                }
            });
        });
    }

    private void handleBackup(CommandSender sender) {
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                Path dest = plugin.getBackupManager().backupNow();
                plugin.getBackupManager().prune();
                plugin.getServer().getScheduler().runTask(plugin, () ->
                        sender.sendMessage(Component.text(
                                "Backup OK: " + (dest != null ? dest.getFileName() : "?"),
                                NamedTextColor.GREEN)));
                if (plugin.getWebhookNotifier() != null) {
                    plugin.getWebhookNotifier().alertAdmin("backup", sender.getName(), dest != null ? dest.getFileName().toString() : "?");
                }
            } catch (Exception e) {
                plugin.getLogger().log(Level.SEVERE, "Backup failed", e);
                plugin.getServer().getScheduler().runTask(plugin, () ->
                        sender.sendMessage(Component.text("Backup failed: " + e.getMessage(), NamedTextColor.RED)));
            }
        });
    }

    private static String redact(String s) {
        if (s == null || s.length() < 5) return "****";
        return "****" + s.substring(s.length() - 4);
    }
}
