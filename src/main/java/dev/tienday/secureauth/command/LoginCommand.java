package dev.tienday.secureauth.command;

import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.database.PlayerData;
import dev.tienday.secureauth.listener.AuthListener;
import dev.tienday.secureauth.security.PasswordUtil;
import dev.tienday.secureauth.security.RateLimiter;
import dev.tienday.secureauth.security.TwoFactorManager;
import dev.tienday.secureauth.util.SessionManager;
import org.bukkit.Location;
import org.bukkit.World;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;

public class LoginCommand implements CommandExecutor {

    private final SecureAuthPlugin plugin;

    public LoginCommand(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command,
                             @NotNull String label, @NotNull String[] args) {
        if (!(sender instanceof Player player)) return true;

        UUID playerUuid = player.getUniqueId();
        String uuid = playerUuid.toString();
        SessionManager sessions = plugin.getSessionManager();
        RateLimiter rateLimiter = plugin.getRateLimiter();
        TwoFactorManager twoFaManager = plugin.getTwoFactorManager();

        if (sessions.isAuthenticated(playerUuid)) {
            player.sendMessage(plugin.getConfigManager().getMessage("already-logged-in"));
            return true;
        }

        if (rateLimiter.isLocked(uuid)) {
            long secs = rateLimiter.secondsRemaining(uuid);
            player.sendMessage(plugin.getConfigManager().getMessage("too-many-attempts")
                    .replaceText(b -> b.matchLiteral("{seconds}").replacement(String.valueOf(secs))));
            return true;
        }

        // Case 1: awaiting 2FA code.
        if (sessions.isAwaitingTwoFa(playerUuid)) {
            if (args.length < 1) {
                player.sendMessage(plugin.getConfigManager().getMessage("two-fa-required"));
                return true;
            }
            String code = args[0];

            TwoFactorManager.VerifyResult result = twoFaManager.verifyCode(uuid, code);
            switch (result) {
                case VALID -> {
                    rateLimiter.clearFailures(uuid);
                    sessions.authenticate(playerUuid);
                    AuthListener.revealPlayer(plugin, player);
                    restorePreLoginLocation(player);
                    player.sendMessage(plugin.getConfigManager().getMessage("login-success"));
                    plugin.getLogger().info("[SecureAuth] " + player.getName() + " logged in via 2FA");
                    asyncUpdateLastLogin(uuid);
                    asyncLog(player, "LOGIN_SUCCESS_2FA", "Logged in via Discord 2FA");
                }
                case EXPIRED -> {
                    sessions.invalidate(playerUuid);
                    player.sendMessage(plugin.getConfigManager().getMessage("two-fa-expired"));
                    asyncLog(player, "2FA_CODE_EXPIRED", "Player's 2FA code expired");
                }
                case INVALID -> {
                    boolean lockedOut = rateLimiter.recordFailure(uuid);
                    int remaining = twoFaManager.remainingAttempts(uuid);

                    player.sendMessage(plugin.getConfigManager().getMessage("two-fa-invalid")
                            .replaceText(b -> b.matchLiteral("{remaining}")
                                    .replacement(String.valueOf(remaining))));
                    asyncLog(player, "2FA_CODE_INVALID",
                            "Invalid 2FA code, remaining attempts=" + remaining);

                    if (lockedOut) {
                        long secs = rateLimiter.secondsRemaining(uuid);
                        player.sendMessage(plugin.getConfigManager().getMessage("too-many-attempts")
                                .replaceText(b -> b.matchLiteral("{seconds}")
                                        .replacement(String.valueOf(secs))));
                    }
                }
                case TOO_MANY_ATTEMPTS -> {
                    sessions.invalidate(playerUuid);
                    twoFaManager.clearCode(uuid);
                    rateLimiter.clearFailures(uuid);
                    asyncLog(player, "2FA_TOO_MANY_ATTEMPTS",
                            "Exceeded max 2FA attempts; kicked.");
                    player.kick(plugin.getConfigManager()
                            .getMessageNoPrefix("kick-2fa-too-many-attempts"));
                }
                case NOT_FOUND -> player.sendMessage(
                        plugin.getConfigManager().getMessage("two-fa-required"));
            }
            return true;
        }

        // Case 2: password login.
        if (args.length < 1) {
            player.sendMessage(plugin.getConfigManager().getMessage("not-logged-in"));
            return true;
        }
        final String password = args[0];

        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                Optional<PlayerData> dataOpt = plugin.getDatabaseManager().getPlayer(uuid);
                if (dataOpt.isEmpty()) {
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (player.isOnline()) {
                            player.sendMessage(plugin.getConfigManager().getMessage("not-registered"));
                        }
                    });
                    return;
                }
                PlayerData data = dataOpt.get();

                boolean passwordOk = PasswordUtil.verify(password, data.getPasswordHash());
                if (!passwordOk) {
                    boolean lockedOut = rateLimiter.recordFailure(uuid);
                    int cnt = rateLimiter.getFailureCount(uuid);
                    asyncLog(player, "LOGIN_FAIL", "Wrong password, attempt #" + cnt);

                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (!player.isOnline()) return;
                        player.sendMessage(plugin.getConfigManager().getMessage("wrong-password"));
                        if (lockedOut) {
                            long secs = rateLimiter.secondsRemaining(uuid);
                            player.sendMessage(plugin.getConfigManager().getMessage("too-many-attempts")
                                    .replaceText(b -> b.matchLiteral("{seconds}")
                                            .replacement(String.valueOf(secs))));
                        }
                    });
                    return;
                }

                if (data.isDisabled()) {
                    asyncLog(player, "LOGIN_DISABLED", "Disabled account attempted login");
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (player.isOnline()) {
                            player.kick(plugin.getConfigManager()
                                    .getMessageNoPrefix("kick-account-disabled"));
                        }
                    });
                    return;
                }

                rateLimiter.clearFailures(uuid);

                if (data.isTwoFaEnabled() && data.getDiscordId() != null) {
                    if (twoFaManager.hasPendingCode(uuid)) {
                        sessions.setAwaitingTwoFa(playerUuid);
                        plugin.getServer().getScheduler().runTask(plugin, () -> {
                            if (player.isOnline()) {
                                player.sendMessage(plugin.getConfigManager().getMessage("two-fa-required"));
                            }
                        });
                        return;
                    }

                    sessions.setAwaitingTwoFa(playerUuid);
                    TwoFactorManager.SendResult sendResult =
                            twoFaManager.generateAndSend(uuid, data.getDiscordId());

                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (!player.isOnline()) return;
                        switch (sendResult) {
                            case SENT -> player.sendMessage(
                                    plugin.getConfigManager().getMessage("two-fa-required"));
                            case COOLDOWN -> {
                                long secs = twoFaManager.getResendCooldownSeconds(uuid);
                                player.sendMessage(plugin.getConfigManager().getMessage("two-fa-cooldown")
                                        .replaceText(b -> b.matchLiteral("{seconds}")
                                                .replacement(String.valueOf(secs))));
                            }
                            case FAILED -> {
                                sessions.invalidate(playerUuid);
                                asyncLog(player, "2FA_DM_FAILED", "Could not send 2FA DM");
                                player.kick(plugin.getConfigManager()
                                        .getMessageNoPrefix("kick-2fa-dm-failed"));
                            }
                        }
                    });
                    return;
                }

                plugin.getServer().getScheduler().runTask(plugin, () -> finalizeLogin(player));
            } catch (Throwable t) {
                plugin.getLogger().log(Level.SEVERE, "Unexpected login error", t);
            }
        });

        return true;
    }

    private void finalizeLogin(Player player) {
        if (!player.isOnline()) return;
        UUID uuid = player.getUniqueId();
        plugin.getSessionManager().authenticate(uuid);
        AuthListener.revealPlayer(plugin, player);
        restorePreLoginLocation(player);
        player.sendMessage(plugin.getConfigManager().getMessage("login-success"));
        plugin.getLogger().info("[SecureAuth] " + player.getName() + " logged in");
        asyncUpdateLastLogin(uuid.toString());
        asyncLog(player, "LOGIN_SUCCESS", "Password login");
    }

    /** FIX: teleport player về vị trí trước khi vào The End, fallback về spawn. */
    /** Teleport player về vị trí trước khi vào The End, fallback về spawn. */
private void restorePreLoginLocation(Player player) {
    UUID uuid = player.getUniqueId();
    Location saved = plugin.getSessionManager().getPreLoginLocation(uuid);   // ← FIX
    if (saved != null && saved.getWorld() != null) {
        player.teleport(saved);
        plugin.getSessionManager().clearPreLoginLocation(uuid);              // ← FIX
    } else {
        World main = plugin.getServer().getWorlds().isEmpty()
                ? null : plugin.getServer().getWorlds().get(0);
        if (main != null) player.teleport(main.getSpawnLocation());
    }
}

    private void asyncUpdateLastLogin(String uuid) {
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin,
                () -> plugin.getDatabaseManager().updateLastLogin(uuid));
    }

    private void asyncLog(Player player, String eventType, String detail) {
        String uuid = player.getUniqueId().toString();
        String name = player.getName();
        final String ip = safeIp(player);
        plugin.getLogger().warning("[SecureAuth][" + eventType + "] " + name + " (" + ip + "): " + detail);

        Runnable task = () -> plugin.getDatabaseManager().logEvent(uuid, name, ip, eventType, detail);
        if (plugin.getServer().isPrimaryThread()) {
            plugin.getServer().getScheduler().runTaskAsynchronously(plugin, task);
        } else {
            task.run();
        }
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
