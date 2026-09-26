package dev.tienday.secureauth.command;

import dev.tienday.secureauth.SecureAuthPlugin;
import dev.tienday.secureauth.database.PlayerData;
import dev.tienday.secureauth.security.PasswordUtil;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

import java.util.Optional;
import java.util.logging.Level;

public class ChangePasswordCommand implements CommandExecutor {

    private static final int MIN_LEN = 8;
    private static final int MAX_LEN = 128;

    private final SecureAuthPlugin plugin;

    public ChangePasswordCommand(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command,
                             @NotNull String label, @NotNull String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(Component.text("Players only.", NamedTextColor.RED));
            return true;
        }

        if (!plugin.getSessionManager().isAuthenticated(player.getUniqueId())) {
            player.sendMessage(plugin.getConfigManager().getMessage("not-logged-in"));
            return true;
        }

        if (args.length < 3) {
            player.sendMessage(Component.text(
                    "Usage: /changepassword <old> <new> <confirm>", NamedTextColor.YELLOW));
            return true;
        }

        String oldPass = args[0];
        String newPass = args[1];
        String confirm = args[2];

        if (newPass.length() < MIN_LEN || newPass.length() > MAX_LEN) {
            player.sendMessage(plugin.getConfigManager().getMessage("password-too-short"));
            return true;
        }
        if (!newPass.equals(confirm)) {
            player.sendMessage(plugin.getConfigManager().getMessage("password-mismatch"));
            return true;
        }
        if (oldPass.equals(newPass)) {
            player.sendMessage(Component.text(
                    "New password must differ from the old one.", NamedTextColor.RED));
            return true;
        }

        String uuid = player.getUniqueId().toString();
        if (!plugin.getRateLimiter().tryAcquireToken("cpw:" + uuid, 3, 60_000L)) {
            player.sendMessage(plugin.getConfigManager().getMessage("too-many-attempts")
                    .replaceText(b -> b.matchLiteral("{seconds}").replacement("60")));
            return true;
        }

        String ip = safeIp(player);
        String name = player.getName();

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

                if (!PasswordUtil.verify(oldPass, dataOpt.get().getPasswordHash())) {
                    plugin.getDatabaseManager().logEvent(uuid, name, ip,
                            "CHANGEPASS_WRONG_OLD", "Wrong old password");
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (player.isOnline()) {
                            player.sendMessage(plugin.getConfigManager().getMessage("wrong-password"));
                        }
                    });
                    return;
                }

                String newHash = PasswordUtil.hash(newPass);
                // Keep Discord + 2FA
                plugin.getDatabaseManager().resetPasswordKeepLink(uuid, newHash);
                plugin.getDatabaseManager().logEvent(uuid, name, ip,
                        "CHANGEPASS_SUCCESS", "Password changed");

                plugin.getServer().getScheduler().runTask(plugin, () -> {
                    if (player.isOnline()) {
                        player.sendMessage(plugin.getConfigManager().getMessage("password-changed"));
                    }
                });
            } catch (Throwable t) {
                plugin.getLogger().log(Level.SEVERE, "ChangePassword error", t);
            }
        });

        return true;
    }

    private static String safeIp(Player player) {
        try {
            if (player.getAddress() != null && player.getAddress().getAddress() != null) {
                return player.getAddress().getAddress().getHostAddress();
            }
        } catch (Exception ignored) {}
        return "unknown";
    }
}
