package dev.tienday.secureauth.command;

import dev.tienday.secureauth.SecureAuthPlugin;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.Location;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

/**
 * /authsetspawn — lưu vị trí hiện tại làm nơi tp player khi chưa login.
 * Yêu cầu permission: secureauth.admin
 *
 * Lưu vào config.yml section login-world.
 */
public class SetSpawnCommand implements CommandExecutor {

    private final SecureAuthPlugin plugin;

    public SetSpawnCommand(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command,
                             @NotNull String label, @NotNull String[] args) {

        if (!sender.hasPermission("secureauth.admin")) {
            sender.sendMessage(Component.text("No permission.", NamedTextColor.RED));
            return true;
        }

        if (!(sender instanceof Player player)) {
            sender.sendMessage(Component.text("Only players can use this command.", NamedTextColor.RED));
            return true;
        }

        Location loc = player.getLocation();

        // Lưu world name và tọa độ vào config
        plugin.getConfig().set("login-world.end-world", loc.getWorld().getName());
        plugin.getConfig().set("login-world.x",   loc.getX());
        plugin.getConfig().set("login-world.y",   loc.getY());
        plugin.getConfig().set("login-world.z",   loc.getZ());
        plugin.getConfig().set("login-world.yaw",   (double) loc.getYaw());
        plugin.getConfig().set("login-world.pitch", (double) loc.getPitch());
        plugin.saveConfig();

        player.sendMessage(Component.text(
                String.format("§a[SecureAuth] Login spawn set: §f%s §7@ §f%.2f, %.2f, %.2f",
                        loc.getWorld().getName(), loc.getX(), loc.getY(), loc.getZ()),
                NamedTextColor.GREEN));

        plugin.getLogger().info("[SecureAuth] Login spawn updated by " + player.getName()
                + " → " + loc.getWorld().getName()
                + " " + loc.getX() + " " + loc.getY() + " " + loc.getZ());

        return true;
    }
}
