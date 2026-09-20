package dev.tienday.secureauth.command;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.event.HoverEvent;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

public class UUIDCommand implements CommandExecutor {

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
