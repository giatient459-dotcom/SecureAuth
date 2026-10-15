package dev.tienday.secureauth.command;

import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.security.PasswordPolicy;
import dev.tienday.secureauth.security.PasswordUtil;
import dev.tienday.secureauth.security.RateLimiter;
import dev.tienday.secureauth.util.IpUtil;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitTask;
import org.jetbrains.annotations.NotNull;

import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Level;

public class RegisterCommand implements CommandExecutor {

    private static final int MAX_PASSWORD_LENGTH = 128;
    private static final long CAPTCHA_TTL_MS = 5 * 60_000L;
    private static final int CAPTCHA_MAX_ATTEMPTS = 3;

    private final SecureAuthPlugin plugin;
    private final Map<UUID, CaptchaChallenge> captchaChallenges = new ConcurrentHashMap<>();
    private BukkitTask cleanupTask;

    private record CaptchaChallenge(int answer, long expiresAt, int attempts) {
        CaptchaChallenge withAttempt() {
            return new CaptchaChallenge(answer, expiresAt, attempts + 1);
        }
    }

    public RegisterCommand(SecureAuthPlugin plugin) {
        this.plugin = plugin;
        // Issue #7 — periodic captcha cleanup
        cleanupTask = plugin.getServer().getScheduler().runTaskTimerAsynchronously(
                plugin, this::cleanupExpiredCaptchas, 20L * 60, 20L * 60);
    }

    /** Call from AuthListener.onQuit */
    public void clearCaptcha(UUID uuid) {
        if (uuid != null) captchaChallenges.remove(uuid);
    }

    public void shutdown() {
        if (cleanupTask != null) {
            cleanupTask.cancel();
            cleanupTask = null;
        }
        captchaChallenges.clear();
    }

    private void cleanupExpiredCaptchas() {
        long now = System.currentTimeMillis();
        captchaChallenges.entrySet().removeIf(e -> now > e.getValue().expiresAt());
    }

    private void issueCaptcha(Player player, UUID playerUuid) {
        // Wider range reduces brute-force (answers 2..100)
        int a = ThreadLocalRandom.current().nextInt(1, 51);
        int b = ThreadLocalRandom.current().nextInt(1, 51);
        long exp = System.currentTimeMillis() + CAPTCHA_TTL_MS;
        captchaChallenges.put(playerUuid, new CaptchaChallenge(a + b, exp, 0));
        player.sendMessage(plugin.getConfigManager().getMessage("captcha-required")
                .replaceText(builder -> builder.matchLiteral("{a}").replacement(String.valueOf(a)))
                .replaceText(builder -> builder.matchLiteral("{b}").replacement(String.valueOf(b))));
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command,
                             @NotNull String label, @NotNull String[] args) {
        if (!(sender instanceof Player player)) return true;

        UUID playerUuid = player.getUniqueId();

        if (plugin.getSessionManager().isAuthenticated(playerUuid)) {
            player.sendMessage(plugin.getConfigManager().getMessage("already-logged-in"));
            return true;
        }

        int minLen = plugin.getConfigManager().getPasswordMinLength();
        boolean captchaOn = plugin.getConfigManager().isRegisterCaptchaEnabled();
        int needArgs = captchaOn ? 3 : 2;

        if (args.length < needArgs) {
            if (captchaOn) {
                issueCaptcha(player, playerUuid);
            } else {
                player.sendMessage(plugin.getConfigManager().getMessage("not-registered"));
            }
            return true;
        }

        String password = args[0];
        String confirm  = args[1];

        if (password.length() < minLen || password.length() > MAX_PASSWORD_LENGTH) {
            player.sendMessage(plugin.getConfigManager().getMessage("password-too-short"));
            return true;
        }

        boolean requireMixed = plugin.getConfigManager().isPasswordRequireMixed();
        double minEntropy = plugin.getConfig().getDouble("security.password.min-entropy-bits", 0);
        if (!PasswordPolicy.isStrong(password, minLen, requireMixed, minEntropy)) {
            player.sendMessage(plugin.getConfigManager().getMessage("password-weak")
                    .replaceText(b -> b.matchLiteral("{min}").replacement(String.valueOf(minLen))));
            return true;
        }

        if (!password.equals(confirm)) {
            player.sendMessage(plugin.getConfigManager().getMessage("password-mismatch"));
            return true;
        }

        if (captchaOn) {
            CaptchaChallenge ch = captchaChallenges.get(playerUuid);
            long now = System.currentTimeMillis();
            if (ch == null || now > ch.expiresAt()) {
                captchaChallenges.remove(playerUuid);
                issueCaptcha(player, playerUuid);
                player.sendMessage(plugin.getConfigManager().getMessage("captcha-wrong"));
                return true;
            }
            int given;
            try {
                given = Integer.parseInt(args[2].trim());
            } catch (NumberFormatException e) {
                CaptchaChallenge next = ch.withAttempt();
                if (next.attempts() >= CAPTCHA_MAX_ATTEMPTS) {
                    captchaChallenges.remove(playerUuid);
                    plugin.getLogger().info("[SecureAuth] Captcha locked out " + player.getName());
                } else {
                    captchaChallenges.put(playerUuid, next);
                }
                player.sendMessage(plugin.getConfigManager().getMessage("captcha-wrong"));
                return true;
            }
            if (given != ch.answer()) {
                CaptchaChallenge next = ch.withAttempt();
                if (next.attempts() >= CAPTCHA_MAX_ATTEMPTS) {
                    captchaChallenges.remove(playerUuid);
                    plugin.getLogger().warning("[SecureAuth] Captcha max attempts for " + player.getName());
                } else {
                    captchaChallenges.put(playerUuid, next);
                }
                player.sendMessage(plugin.getConfigManager().getMessage("captcha-wrong"));
                return true;
            }
            captchaChallenges.remove(playerUuid);
        }

        RateLimiter rateLimiter = plugin.getRateLimiter();
        String uuid = playerUuid.toString();
        String username = player.getName();
        final String ip = IpUtil.safeIp(player);

        // Issue #2 — null IP cannot register (prevents bypass of IP limits)
        if (ip == null) {
            player.sendMessage(plugin.getConfigManager().getMessage("not-registered"));
            plugin.getLogger().warning("[SecureAuth] Register blocked — no valid IP for " + username);
            return true;
        }

        if (!rateLimiter.tryAcquireToken("reg:" + ip, plugin.getConfigManager().getRegisterAttemptsPer10Min(), 600_000L)) {
            player.sendMessage(plugin.getConfigManager().getMessage("register-rate-limited"));
            return true;
        }

        final int maxPerIp = plugin.getConfigManager().getMaxAccountsPerIp();
        final String passwordFinal = password;

        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                if (plugin.getDatabaseManager().isRegistered(uuid)) {
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (player.isOnline()) {
                            player.sendMessage(plugin.getConfigManager().getMessage("already-registered"));
                        }
                    });
                    return;
                }

                if (maxPerIp > 0 && plugin.getDatabaseManager().countAccountsByIp(ip) >= maxPerIp) {
                    plugin.getDatabaseManager().logEvent(uuid, username, ip,
                            "REGISTER_IP_LIMIT", "IP limit reached");
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (player.isOnline()) {
                            player.sendMessage(plugin.getConfigManager().getMessage("register-ip-limit"));
                        }
                    });
                    return;
                }

                String hash = PasswordUtil.hash(passwordFinal);
                boolean inserted = plugin.getDatabaseManager()
                        .registerPlayer(uuid, username, hash, ip);

                if (inserted) {
                    plugin.getLogger().info("[SecureAuth] New registration: " + username);
                    plugin.getDatabaseManager().logEvent(uuid, username, ip,
                            "REGISTER_SUCCESS", "New account created");
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (!player.isOnline()) return;
                        plugin.getSessionManager().authenticate(playerUuid, IpUtil.safeIp(player));
                        plugin.getSessionManager().restoreLocationAfterLogin(player);
                        dev.tienday.secureauth.listener.AuthListener.revealPlayer(plugin, player);
                        player.sendMessage(plugin.getConfigManager().getMessage("register-success"));
                    });
                } else {
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (player.isOnline()) {
                            player.sendMessage(plugin.getConfigManager().getMessage("already-registered"));
                        }
                    });
                }
            } catch (Throwable t) {
                plugin.getLogger().log(Level.SEVERE, "Registration error for " + username, t);
            }
        });

        return true;
    }
}
