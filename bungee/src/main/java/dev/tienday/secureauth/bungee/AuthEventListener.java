package dev.tienday.secureauth.bungee;

import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.config.ServerInfo;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.ChatEvent;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;

import java.util.UUID;

public final class AuthEventListener implements Listener {

    private final SecureAuthBungee plugin;

    public AuthEventListener(SecureAuthBungee plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOW)
    public void onServerConnect(ServerConnectEvent event) {
        ProxiedPlayer player = event.getPlayer();
        UUID uuid = player.getUniqueId();
        if (plugin.getSessionStore().isAuthenticated(uuid)) {
            return;
        }

        String authServer = plugin.getPluginConfig().getAuthServer();
        String target = event.getTarget() != null ? event.getTarget().getName() : "";

        // Allow connect to designated auth/lobby server
        if (!authServer.isBlank() && target.equalsIgnoreCase(authServer)) {
            return;
        }

        if (!authServer.isBlank()) {
            ServerInfo lobby = plugin.getProxy().getServerInfo(authServer);
            if (lobby != null) {
                event.setTarget(lobby);
                return;
            }
            plugin.getLogger().warning("[SecureAuthBungee] auth-server '" + authServer
                    + "' not found in Bungee config");
        }

        event.setCancelled(true);
        player.disconnect(new TextComponent(ChatColor.RED + "You must log in first."));
    }

    @EventHandler(priority = EventPriority.LOW)
    public void onChat(ChatEvent event) {
        if (!(event.getSender() instanceof ProxiedPlayer player)) return;
        if (plugin.getSessionStore().isAuthenticated(player.getUniqueId())) return;

        // Block proxy commands until authenticated (Paper still handles /login on backend)
        if (event.isCommand()) {
            String cmd = event.getMessage().toLowerCase();
            if (cmd.startsWith("/server") || cmd.startsWith("/send") || cmd.startsWith("/hub")
                    || cmd.startsWith("/lobby") || cmd.startsWith("/goto")) {
                event.setCancelled(true);
                player.sendMessage(new TextComponent(ChatColor.RED + "Log in first."));
            }
        }
    }

    @EventHandler
    public void onDisconnect(PlayerDisconnectEvent event) {
        plugin.getSessionStore().clear(event.getPlayer().getUniqueId());
    }
}
