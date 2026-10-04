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
 * /authsetspawn | /setlobby — lưu vị trí hiện tại làm nơi giữ player chưa login.
 * Giống AuthMe setspawn: đứng đâu cũng được (Lobby, limbo, world...).
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
        if (loc.getWorld() == null) {
            sender.sendMessage(Component.text("Invalid world.", NamedTextColor.RED));
            return true;
        }

        String worldName = loc.getWorld().getName();
        plugin.getConfig().set("login-world.world", worldName);
        plugin.getConfig().set("login-world.end-world", worldName); // tương thích cũ
        plugin.getConfig().set("login-world.x", loc.getX());
        plugin.getConfig().set("login-world.y", loc.getY());
        plugin.getConfig().set("login-world.z", loc.getZ());
        plugin.getConfig().set("login-world.yaw", (double) loc.getYaw());
        plugin.getConfig().set("login-world.pitch", (double) loc.getPitch());
        plugin.getConfigManager().saveSectionToFile("login-world", "login-world.yml");
        // keep in-memory config in sync
        plugin.saveConfig();

        player.sendMessage(Component.text(
                String.format("Login lobby set: %s @ %.2f, %.2f, %.2f",
                        worldName, loc.getX(), loc.getY(), loc.getZ()),
                NamedTextColor.GREEN));

        plugin.getLogger().info("[SecureAuth] Login lobby by " + player.getName()
                + " → " + worldName + " " + loc.getX() + " " + loc.getY() + " " + loc.getZ());

        return true;
    }
}
