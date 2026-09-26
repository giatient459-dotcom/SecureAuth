package dev.tienday.secureauth.velocity;

import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;

import java.util.Optional;
import java.util.UUID;

public final class AuthEventListener {

    private static final Component KICK_NOT_AUTH = Component.text(
            "You must log in first.", NamedTextColor.RED);

    private final SecureAuthVelocity plugin;

    public AuthEventListener(SecureAuthVelocity plugin) {
        this.plugin = plugin;
    }

    @Subscribe(order = PostOrder.EARLY)
    public void onServerPreConnect(ServerPreConnectEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();

        if (plugin.getSessionStore().isAuthenticated(uuid)) {
            return;
        }

        String authServer = plugin.getPluginConfig().getAuthServer();
        Optional<String> target = event.getResult().getServer()
                .map(s -> s.getServerInfo().getName());

        // Allow connecting to the designated auth/lobby server
        if (!authServer.isBlank() && target.map(n -> n.equalsIgnoreCase(authServer)).orElse(false)) {
            return;
        }

        if (!authServer.isBlank()) {
            Optional<RegisteredServer> lobby = plugin.getServer().getServer(authServer);
            if (lobby.isPresent()) {
                event.setResult(ServerPreConnectEvent.ServerResult.allowed(lobby.get()));
                return;
            }
            plugin.getLogger().warn("[SecureAuthVelocity] auth-server '{}' not found in velocity.toml",
                    authServer);
        }

        event.setResult(ServerPreConnectEvent.ServerResult.denied());
        player.disconnect(KICK_NOT_AUTH);
    }

    @Subscribe(order = PostOrder.EARLY)
    public void onCommand(CommandExecuteEvent event) {
        if (!(event.getCommandSource() instanceof Player player)) return;
        if (plugin.getSessionStore().isAuthenticated(player.getUniqueId())) return;

        String cmd = event.getCommand().toLowerCase();
        // Allow nothing at proxy level until authed (Paper handles /login on auth server)
        // Optional: allow server-specific commands later
        if (cmd.startsWith("server ") || cmd.equals("server")) {
            event.setResult(CommandExecuteEvent.CommandResult.denied());
            player.sendMessage(Component.text(
                    "Log in before switching servers.", NamedTextColor.RED));
        }
    }

    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        plugin.getSessionStore().invalidate(event.getPlayer().getUniqueId());
    }
}
