package dev.tienday.secureauth.command;

import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.security.PasswordUtil;
import dev.tienday.secureauth.security.RateLimiter;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

import java.util.UUID;
import java.util.logging.Level;

public class RegisterCommand implements CommandExecutor {

    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_LENGTH = 128;

    private final SecureAuthPlugin plugin;

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

        if (args.length < 2) {
            player.sendMessage(plugin.getConfigManager().getMessage("not-registered"));
            return true;
        }

        String password = args[0];
        String confirm  = args[1];

        if (password.length() < MIN_PASSWORD_LENGTH || password.length() > MAX_PASSWORD_LENGTH) {
            player.sendMessage(plugin.getConfigManager().getMessage("password-too-short"));
            return true;
        }
        if (!password.equals(confirm)) {
            player.sendMessage(plugin.getConfigManager().getMessage("password-mismatch"));
            return true;
        }

        RateLimiter rateLimiter = plugin.getRateLimiter();
        String rlKey = "register:" + playerUuid;
        if (!rateLimiter.tryAcquireToken(rlKey,
                plugin.getConfigManager().getRegisterAttemptsPer10Min(), 10 * 60_000L)) {
            player.sendMessage(plugin.getConfigManager().getMessage("register-rate-limited"));
            return true;
        }

        String uuid     = playerUuid.toString();
        String username = player.getName();

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

                // Kiểm tra giới hạn account theo IP
                int maxPerIp = plugin.getConfigManager().getMaxAccountsPerIp();
                if (maxPerIp > 0) {
                    String ip = safeIp(player);
                    int count = plugin.getDatabaseManager().countAccountsByIp(ip);
                    if (count >= maxPerIp) {
                        plugin.getDatabaseManager().logEvent(uuid, username, ip,
                                "REGISTER_IP_LIMIT", "IP limit reached: " + count + "/" + maxPerIp);
                        plugin.getAuditLogger().log("REGISTER_IP_LIMIT", username, uuid, ip,
                                "IP already has " + count + " accounts");
                        plugin.getServer().getScheduler().runTask(plugin, () -> {
                            if (player.isOnline()) player.sendMessage(
                                    net.kyori.adventure.text.Component.text(
                                            "§cIP của bạn đã đạt giới hạn số tài khoản (" + maxPerIp + ").",
                                            net.kyori.adventure.text.format.NamedTextColor.RED));
                        });
                        return;
                    }
                }

                String hash = PasswordUtil.hash(password);
                boolean inserted = plugin.getDatabaseManager().registerPlayer(uuid, username, hash);

                if (inserted) {
                    plugin.getLogger().info("[SecureAuth] New registration: " + username);
                    plugin.getDatabaseManager().logEvent(uuid, username, safeIp(player),
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
