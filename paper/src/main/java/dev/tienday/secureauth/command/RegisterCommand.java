package dev.tienday.secureauth.command;

import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.security.PasswordUtil;
import dev.tienday.secureauth.security.RateLimiter;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Level;

public class RegisterCommand implements CommandExecutor {

    private static final int MAX_PASSWORD_LENGTH = 128;

    private final SecureAuthPlugin plugin;
    /** uuid -> expected captcha answer */
    private final Map<UUID, Integer> captchaAnswers = new ConcurrentHashMap<>();

    public RegisterCommand(SecureAuthPlugin plugin) {
        this.plugin = plugin;
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
                int a = ThreadLocalRandom.current().nextInt(1, 10);
                int b = ThreadLocalRandom.current().nextInt(1, 10);
                captchaAnswers.put(playerUuid, a + b);
                player.sendMessage(plugin.getConfigManager().getMessage("captcha-required")
                        .replaceText(builder -> builder.matchLiteral("{a}").replacement(String.valueOf(a)))
                        .replaceText(builder -> builder.matchLiteral("{b}").replacement(String.valueOf(b))));
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
        if (plugin.getConfigManager().isPasswordRequireMixed()) {
            boolean hasLetter = password.chars().anyMatch(Character::isLetter);
            boolean hasDigit  = password.chars().anyMatch(Character::isDigit);
            if (!hasLetter || !hasDigit) {
                player.sendMessage(plugin.getConfigManager().getMessage("password-weak")
                        .replaceText(b -> b.matchLiteral("{min}").replacement(String.valueOf(minLen))));
                return true;
            }
        }
        if (!password.equals(confirm)) {
            player.sendMessage(plugin.getConfigManager().getMessage("password-mismatch"));
            return true;
        }

        if (captchaOn) {
            Integer expected = captchaAnswers.get(playerUuid);
            if (expected == null) {
                int a = ThreadLocalRandom.current().nextInt(1, 10);
                int b = ThreadLocalRandom.current().nextInt(1, 10);
                captchaAnswers.put(playerUuid, a + b);
                player.sendMessage(plugin.getConfigManager().getMessage("captcha-required")
                        .replaceText(builder -> builder.matchLiteral("{a}").replacement(String.valueOf(a)))
                        .replaceText(builder -> builder.matchLiteral("{b}").replacement(String.valueOf(b))));
                return true;
            }
            try {
                int given = Integer.parseInt(args[2].trim());
                if (given != expected) {
                    captchaAnswers.remove(playerUuid);
                    player.sendMessage(plugin.getConfigManager().getMessage("captcha-wrong"));
                    return true;
                }
            } catch (NumberFormatException e) {
                player.sendMessage(plugin.getConfigManager().getMessage("captcha-wrong"));
                return true;
            }
            captchaAnswers.remove(playerUuid);
        }

        RateLimiter rateLimiter = plugin.getRateLimiter();
        String rlKey = "register:" + playerUuid;
        if (!rateLimiter.tryAcquireToken(rlKey,
                plugin.getConfigManager().getRegisterAttemptsPer10Min(), 10 * 60_000L)) {
            player.sendMessage(plugin.getConfigManager().getMessage("register-rate-limited"));
            return true;
        }

        final String uuid     = playerUuid.toString();
        final String username = player.getName();
        final String ip       = safeIp(player);
        final int maxPerIp    = plugin.getConfigManager().getMaxAccountsPerIp();

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

                String hash = PasswordUtil.hash(password);
                boolean inserted = plugin.getDatabaseManager()
                        .registerPlayer(uuid, username, hash, ip);

                if (inserted) {
                    plugin.getLogger().info("[SecureAuth] New registration: " + username);
                    plugin.getDatabaseManager().logEvent(uuid, username, ip,
                            "REGISTER_SUCCESS", "New account created");
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (player.isOnline()) {
                            player.sendMessage(plugin.getConfigManager().getMessage("register-success"));
                        }
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

    private static String safeIp(Player player) {
        try {
            if (player.getAddress() != null && player.getAddress().getAddress() != null) {
                return player.getAddress().getAddress().getHostAddress();
            }
        } catch (Exception ignored) { }
        return "unknown";
    }
}
