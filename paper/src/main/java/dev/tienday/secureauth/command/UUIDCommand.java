package dev.tienday.secureauth.command;

import dev.tienday.secureauth.SecureAuthPlugin;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.event.HoverEvent;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

/**
 * /uuid — show own UUID. No Mojang lookup.
 */
public class UUIDCommand implements CommandExecutor {

    public UUIDCommand(SecureAuthPlugin plugin) {
        // reserved for future admin lookup via DB
    }

    public UUIDCommand() {}

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command,
                             @NotNull String label, @NotNull String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(Component.text("Only players can use this command.", NamedTextColor.RED));
            return true;
        }

        String uuid = player.getUniqueId().toString();
        player.sendMessage(Component.text("Your UUID: ", NamedTextColor.GRAY)
                .append(Component.text(uuid, NamedTextColor.YELLOW)
                        .clickEvent(ClickEvent.copyToClipboard(uuid))
                        .hoverEvent(HoverEvent.showText(
                                Component.text("Click to copy", NamedTextColor.AQUA)))));
        return true;
    }
}
