package dev.tienday.secureauth.command;

import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.database.PlayerData;
import dev.tienday.secureauth.listener.AuthListener;
import dev.tienday.secureauth.security.PasswordUtil;
import dev.tienday.secureauth.security.PremiumChecker;
import dev.tienday.secureauth.security.RateLimiter;
import dev.tienday.secureauth.security.TwoFactorManager;
import dev.tienday.secureauth.util.SessionManager;
import dev.tienday.secureauth.util.TitleUtil;
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

        // Case 1: awaiting 2FA / IP confirm
        if (sessions.isAwaitingTwoFa(playerUuid)) {
            // IP confirm buttons — không cần gõ mã
            if (twoFaManager.hasPendingIpConfirm(uuid)) {
                TitleUtil.ipConfirmPrompt(player);
                player.sendMessage(plugin.getConfigManager().getMessage("ip-confirm-waiting"));
                return true;
            }
            if (args.length < 1) {
                player.sendMessage(plugin.getConfigManager().getMessage("two-fa-required"));
                return true;
            }
            String code = args[args.length == 1 ? 0 : 1];

            TwoFactorManager.VerifyResult result = twoFaManager.verifyCode(uuid, code);
            switch (result) {
                case VALID -> {
                    sessions.authenticate(playerUuid);
                    plugin.getSessionManager().restoreLocationAfterLogin(player);
                    AuthListener.revealPlayer(plugin, player);
                    TitleUtil.loginSuccess(player);
                    player.sendMessage(plugin.getConfigManager().getMessage("login-success"));
                    plugin.getLogger().info("[SecureAuth] " + player.getName() + " logged in via 2FA");
                    asyncUpdateLastLogin(uuid, player);
                    asyncLog(player, "LOGIN_SUCCESS_2FA", "Logged in via Discord 2FA");
                    if (plugin.getIpSessionStore() != null) {
                        plugin.getIpSessionStore().remember(uuid, safeIp(player));
                    }
                    notifyVelocity(uuid);
                }
                case EXPIRED -> {
                    sessions.invalidate(playerUuid);
                    player.sendMessage(plugin.getConfigManager().getMessage("two-fa-expired"));
                    asyncLog(player, "2FA_CODE_EXPIRED", "Player's 2FA code expired");
                }
                case INVALID -> {
                    boolean lockedOut = rateLimiter.recordFailure(uuid);
                    player.sendMessage(plugin.getConfigManager().getMessage("two-fa-invalid"));
                    asyncLog(player, "2FA_CODE_INVALID",
                            "Invalid 2FA code attempt #" + rateLimiter.getFailureCount(uuid));
                    if (lockedOut) {
                        long secs = rateLimiter.secondsRemaining(uuid);
                        player.sendMessage(plugin.getConfigManager().getMessage("too-many-attempts")
                                .replaceText(b -> b.matchLiteral("{seconds}").replacement(String.valueOf(secs))));
                    }
                }
                case NOT_FOUND -> player.sendMessage(plugin.getConfigManager().getMessage("two-fa-required"));
            }
            return true;
        }

        // Case 2: password login.
        if (args.length < 1) {
            player.sendMessage(plugin.getConfigManager().getMessage("not-logged-in"));
            return true;
        }
        final String password = args[0];
        // Snapshot Bukkit state before entering the async database/hash task.
        final String loginIp = safeIp(player);
        final String playerName = player.getName();
        final boolean force2fa = player.hasPermission("secureauth.force2fa");

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
                    asyncLog(uuid, playerName, loginIp,
                            "LOGIN_FAIL", "Wrong password, attempt #" + cnt);
                    if (lockedOut && plugin.getWebhookNotifier() != null) {
                        plugin.getWebhookNotifier().alertLockout(
                                playerName, uuid, loginIp, cnt);
                    }

                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (!player.isOnline()) return;
                        player.sendMessage(plugin.getConfigManager().getMessage("wrong-password"));
                        if (lockedOut) {
                            long secs = rateLimiter.secondsRemaining(uuid);
                            player.sendMessage(plugin.getConfigManager().getMessage("too-many-attempts")
                                    .replaceText(b -> b.matchLiteral("{seconds}").replacement(String.valueOf(secs))));
                        }
                    });
                    return;
                }

                rateLimiter.clearFailures(uuid);

                final String currentIp = loginIp;
                final boolean ipTrusted = !force2fa
                        && plugin.getIpSessionStore() != null
                        && plugin.getIpSessionStore().isTrusted(uuid, currentIp);

                if (data.isTwoFaEnabled() && data.getDiscordId() != null) {
                    if (ipTrusted) {
                        plugin.getServer().getScheduler().runTask(plugin, () -> {
                            if (!player.isOnline()) return;
                            player.sendMessage(plugin.getConfigManager().getMessage("ip-session-skip-2fa"));
                            finalizeLogin(player);
                        });
                        return;
                    }

                    // IP mới + confirm-buttons → Discord nút Xác nhận / Từ chối
                    if (plugin.getConfigManager().isIpConfirmButtonsEnabled()) {
                        if (twoFaManager.hasPendingIpConfirm(uuid)) {
                            sessions.setAwaitingTwoFa(playerUuid);
                            plugin.getServer().getScheduler().runTask(plugin, () -> {
                                if (!player.isOnline()) return;
                                TitleUtil.ipConfirmPrompt(player);
                                player.sendMessage(plugin.getConfigManager().getMessage("ip-confirm-waiting"));
                            });
                            return;
                        }
                        sessions.setAwaitingTwoFa(playerUuid);
                        TwoFactorManager.SendResult sendResult = twoFaManager.sendIpConfirm(
                                uuid, data.getDiscordId(), playerName, currentIp);
                        plugin.getServer().getScheduler().runTask(plugin, () -> {
                            if (!player.isOnline()) return;
                            switch (sendResult) {
                                case SENT -> {
                                    TitleUtil.ipConfirmPrompt(player);
                                    player.sendMessage(plugin.getConfigManager().getMessage("ip-confirm-sent")
                                            .replaceText(b -> b.matchLiteral("{ip}").replacement(currentIp)));
                                }
                                case COOLDOWN -> {
                                    long secs = twoFaManager.getResendCooldownSeconds(uuid);
                                    player.sendMessage(plugin.getConfigManager().getMessage("two-fa-cooldown")
                                            .replaceText(b -> b.matchLiteral("{seconds}")
                                                    .replacement(String.valueOf(secs))));
                                }
                                case FAILED -> {
                                    sessions.invalidate(playerUuid);
                                    asyncLog(uuid, playerName, currentIp,
                                            "IP_CONFIRM_DM_FAILED", "Could not send IP confirm DM");
                                    player.kick(plugin.getConfigManager()
                                            .getMessageNoPrefix("kick-2fa-dm-failed"));
                                }
                            }
                        });
                        return;
                    }

                    // Fallback: mã 2FA gõ /login <code>
                    if (twoFaManager.hasPendingCode(uuid)) {
                        sessions.setAwaitingTwoFa(playerUuid);
                        plugin.getServer().getScheduler().runTask(plugin, () -> {
                            if (player.isOnline()) {
                                TitleUtil.twoFaPrompt(player);
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
                            case SENT -> {
                                TitleUtil.twoFaPrompt(player);
                                player.sendMessage(plugin.getConfigManager().getMessage("two-fa-required"));
                            }
                            case COOLDOWN -> {
                                long secs = twoFaManager.getResendCooldownSeconds(uuid);
                                player.sendMessage(plugin.getConfigManager().getMessage("two-fa-cooldown")
                                        .replaceText(b -> b.matchLiteral("{seconds}")
                                                .replacement(String.valueOf(secs))));
                            }
                            case FAILED -> {
                                sessions.invalidate(playerUuid);
                                asyncLog(uuid, playerName, currentIp,
                                        "2FA_DM_FAILED", "Could not send 2FA DM");
                                player.kick(plugin.getConfigManager()
                                        .getMessageNoPrefix("kick-2fa-dm-failed"));
                            }
                        }
                    });
                    return;
                }

                // Staff force2fa but not linked yet
                if (force2fa && (data.getDiscordId() == null || data.getDiscordId().isBlank())) {
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (player.isOnline()) {
                            player.sendMessage(plugin.getConfigManager().getMessage("force-2fa-required"));
                        }
                    });
                    return;
                }

                // No 2FA -> complete login.
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
        plugin.getSessionManager().restoreLocationAfterLogin(player);
        AuthListener.revealPlayer(plugin, player);
        TitleUtil.loginSuccess(player);
        player.sendMessage(plugin.getConfigManager().getMessage("login-success"));
        plugin.getLogger().info("[SecureAuth] " + player.getName() + " logged in");
        asyncUpdateLastLogin(uuid.toString(), player);
        asyncLog(player, "LOGIN_SUCCESS", "Password login");
        if (plugin.getIpSessionStore() != null) {
            plugin.getIpSessionStore().remember(uuid.toString(), safeIp(player));
        }
        notifyVelocity(uuid.toString());
    }

    /**
     * Premium auto-login hoặc sau khi Discord approve IP.
     * Gọi từ main thread.
     */
    public void completeLoginFromExternal(Player player, String reason) {
        if (!player.isOnline()) return;
        UUID uuid = player.getUniqueId();
        plugin.getSessionManager().authenticate(uuid);
        plugin.getSessionManager().restoreLocationAfterLogin(player);
        AuthListener.revealPlayer(plugin, player);
        if ("premium".equals(reason)) {
            TitleUtil.premiumAutoLogin(player);
            player.sendMessage(plugin.getConfigManager().getMessage("premium-auto-login"));
        } else {
            TitleUtil.loginSuccess(player);
            player.sendMessage(plugin.getConfigManager().getMessage("ip-confirm-approved"));
        }
        asyncUpdateLastLogin(uuid.toString(), player);
        asyncLog(player, "LOGIN_SUCCESS", reason);
        if (plugin.getIpSessionStore() != null) {
            plugin.getIpSessionStore().remember(uuid.toString(), safeIp(player));
        }
        notifyVelocity(uuid.toString());
    }

    /**
     * Gọi HTTP POST đến Velocity plugin để đánh dấu session authenticated.
     * Chạy async để không block main thread.
     */
    private void notifyVelocity(String uuid) {
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            String velocityUrl = plugin.getConfigManager().getVelocityNotifyUrl();
            if (velocityUrl == null || velocityUrl.isBlank()) return; // Velocity chưa config

            String secret = plugin.getConfigManager().getBackendSecret();
            String body   = "{\"uuid\":\"" + uuid + "\"}";

            try {
                java.net.URL url = java.net.URI.create(velocityUrl).toURL();
                java.net.HttpURLConnection conn =
                        (java.net.HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Authorization", "Bearer " + secret);
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);
                conn.setDoOutput(true);
                try (java.io.OutputStream os = conn.getOutputStream()) {
                    os.write(body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
                int status = conn.getResponseCode();
                conn.disconnect();
                if (status != 200) {
                    plugin.getLogger().warning(
                            "[SecureAuth] Velocity notify returned HTTP " + status);
                }
            } catch (Exception e) {
                plugin.getLogger().warning(
                        "[SecureAuth] Failed to notify Velocity: " + e.getMessage());
            }
        });
    }

    private void asyncUpdateLastLogin(String uuid) {
        asyncUpdateLastLogin(uuid, null);
    }

    private void asyncUpdateLastLogin(String uuid, Player player) {
        final String ip = player != null ? safeIp(player) : null;
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin,
                () -> plugin.getDatabaseManager().updateLastLogin(uuid, ip));
    }

    private void asyncLog(Player player, String eventType, String detail) {
        String uuid = player.getUniqueId().toString();
        String name = player.getName();
        String ip = safeIp(player);
        asyncLog(uuid, name, ip, eventType, detail);
    }

    private void asyncLog(String uuid, String name, String ip,
                          String eventType, String detail) {
        boolean isError = eventType.contains("FAIL") || eventType.contains("BLOCK")
                || eventType.contains("INVALID") || eventType.contains("EXPIRED")
                || eventType.contains("DENIED");
        if (isError) {
            plugin.getLogger().warning("[SecureAuth][" + eventType + "] " + name + " (" + ip + "): " + detail);
        } else {
            plugin.getLogger().info("[SecureAuth][" + eventType + "] " + name + " (" + ip + "): " + detail);
        }

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
