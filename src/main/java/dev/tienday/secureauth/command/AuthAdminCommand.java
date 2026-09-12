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

        if (args.length < 2) {
            sender.sendMessage(Component.text(
                    "Usage: /authadmin <reset|resetfa|info> <player>", NamedTextColor.YELLOW));
            return true;
        }

        String sub = args[0].toLowerCase();
        String targetName = args[1];

        if (!targetName.matches("[A-Za-z0-9_]{3,16}")) {
            sender.sendMessage(Component.text("Invalid player name.", NamedTextColor.RED));
            return true;
        }

        OfflinePlayer target = resolvePlayer(targetName);
        if (target == null || target.getUniqueId() == null) {
            sender.sendMessage(Component.text("Player not found.", NamedTextColor.RED));
            return true;
        }

        UUID targetUuid = target.getUniqueId();
        String uuid = targetUuid.toString();

        switch (sub) {
            case "reset"   -> handleReset(sender, target, targetUuid, uuid);
            case "resetfa" -> handleResetTwoFa(sender, target, uuid);
            case "info"    -> handleInfo(sender, target, targetUuid, uuid);
            default -> sender.sendMessage(Component.text(
                    "Unknown subcommand. Use: reset | resetfa | info", NamedTextColor.RED));
        }
        return true;
    }

    @SuppressWarnings("deprecation")
    private OfflinePlayer resolvePlayer(String name) {
        Player online = plugin.getServer().getPlayerExact(name);
        if (online != null) return online;

        OfflinePlayer cached = plugin.getServer().getOfflinePlayerIfCached(name);
        if (cached != null && (cached.hasPlayedBefore() || cached.isOnline())
                && cached.getUniqueId() != null) {
            return cached;
        }

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
                plugin.getDatabaseManager().disablePassword(uuid);
                plugin.getDatabaseManager().deleteAllLinkCodesFor(uuid);
                plugin.getTwoFactorManager().clearCode(uuid);
                plugin.getRateLimiter().clearFailures(uuid);
                plugin.getRateLimiter().clearTokens("register:" + uuid);
                plugin.getRateLimiter().clearTokens("link:" + uuid);

                plugin.getDatabaseManager().logEvent(uuid, target.getName(), "admin",
                        "ADMIN_RESET", "Account reset by " + sender.getName());

                plugin.getServer().getScheduler().runTask(plugin, () -> {
                    Player online = plugin.getServer().getPlayer(targetUuid);
                    if (online != null) {
                        plugin.getSessionManager().invalidate(targetUuid);
                        online.kick(Component.text("Your account has been reset by an admin."));
                    }
                    sender.sendMessage(Component.text(
                            "Account reset for " + target.getName() + ". They must /register again.",
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

    private void handleResetTwoFa(CommandSender sender, OfflinePlayer target, String uuid) {
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                plugin.getDatabaseManager().deleteAllLinkCodesFor(uuid);
                plugin.getDatabaseManager().clearDiscordLink(uuid);
                plugin.getTwoFactorManager().clearCode(uuid);

                plugin.getDatabaseManager().logEvent(uuid, target.getName(), "admin",
                        "ADMIN_RESET_2FA", "2FA cleared by " + sender.getName());

                plugin.getServer().getScheduler().runTask(plugin, () ->
                        sender.sendMessage(Component.text(
                                "2FA / Discord link cleared for " + target.getName() + ".",
                                NamedTextColor.GREEN)));
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
                Optional<PlayerData> dataOpt = plugin.getDatabaseManager().getPlayer(uuid);
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
                            "Discord: " + (d.getDiscordId() != null ? redact(d.getDiscordId()) : "not linked"),
                            NamedTextColor.GRAY));
                    sender.sendMessage(Component.text(
                            "2FA enabled: " + d.isTwoFaEnabled(), NamedTextColor.GRAY));
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

    private static String redact(String s) {
        if (s == null || s.length() < 5) return "****";
        return "****" + s.substring(s.length() - 4);
    }
}