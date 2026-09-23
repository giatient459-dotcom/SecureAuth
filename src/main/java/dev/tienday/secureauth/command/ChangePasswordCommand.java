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

/**
 * /changepassword <old_password> <new_password> <confirm_password>
 * Yêu cầu: đã login, biết mật khẩu cũ.
 */
public class ChangePasswordCommand implements CommandExecutor {

    private static final int MIN_LENGTH = 6;
    private final SecureAuthPlugin plugin;

    public ChangePasswordCommand(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command,
                             @NotNull String label, @NotNull String[] args) {
        if (!(sender instanceof Player player)) return true;

        if (!plugin.getSessionManager().isAuthenticated(player.getUniqueId())) {
            player.sendMessage(plugin.getConfigManager().getMessage("not-logged-in"));
            return true;
        }

        if (args.length < 3) {
            player.sendMessage(Component.text(
                    "§eUsage: /changepassword <mật khẩu cũ> <mật khẩu mới> <xác nhận>",
                    NamedTextColor.YELLOW));
            return true;
        }

        String oldPass  = args[0];
        String newPass  = args[1];
        String confirm  = args[2];

        if (newPass.length() < MIN_LENGTH) {
            player.sendMessage(plugin.getConfigManager().getMessage("password-too-short"));
            return true;
        }

        if (!newPass.equals(confirm)) {
            player.sendMessage(plugin.getConfigManager().getMessage("password-mismatch"));
            return true;
        }

        if (oldPass.equals(newPass)) {
            player.sendMessage(Component.text(
                    "§cMật khẩu mới phải khác mật khẩu cũ.", NamedTextColor.RED));
            return true;
        }

        String uuid = player.getUniqueId().toString();

        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
            Optional<PlayerData> dataOpt = plugin.getDatabaseManager().getPlayer(uuid);

            if (dataOpt.isEmpty()) {
                plugin.getServer().getScheduler().runTask(plugin, () ->
                        player.sendMessage(plugin.getConfigManager().getMessage("not-registered")));
                return;
            }

            if (!PasswordUtil.verify(oldPass, dataOpt.get().getPasswordHash())) {
                plugin.getServer().getScheduler().runTask(plugin, () ->
                        player.sendMessage(plugin.getConfigManager().getMessage("wrong-password")));
                plugin.getDatabaseManager().logEvent(uuid, player.getName(), safeIp(player),
                        "CHANGEPASS_WRONG_OLD", "Wrong old password");
                return;
            }

            String newHash = PasswordUtil.hash(newPass);
            plugin.getDatabaseManager().resetPassword(uuid, newHash);

            plugin.getDatabaseManager().logEvent(uuid, player.getName(), safeIp(player),
                    "CHANGEPASS_SUCCESS", "Password changed");
            plugin.getAuditLogger().log("CHANGEPASS_SUCCESS", player.getName(),
                    uuid, safeIp(player), "Password changed successfully");
            plugin.getLogger().info("[SecureAuth] " + player.getName() + " changed password");

            plugin.getServer().getScheduler().runTask(plugin, () ->
                    player.sendMessage(Component.text(
                            "§a[SecureAuth] Đổi mật khẩu thành công!", NamedTextColor.GREEN)));
        });

        return true;
    }

    private static String safeIp(Player player) {
        try {
            if (player.getAddress() != null && player.getAddress().getAddress() != null)
                return player.getAddress().getAddress().getHostAddress();
        } catch (Exception ignored) {}
        return "unknown";
    }
}
