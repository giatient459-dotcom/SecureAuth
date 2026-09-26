package dev.tienday.secureauth.listener;

import dev.tienday.secureauth.SecureAuthPlugin;
import net.kyori.adventure.text.Component;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerCommandSendEvent;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * CommandBlocker — chặn và ẩn tab-complete các command trong blacklist
 * với player đã login nhưng không phải OP.
 *
 * Chạy ở NORMAL priority — sau DangerousCommandListener (LOW) để tránh
 * double-block và message sai với các command server như /reload, /whitelist.
 */
public class CommandBlocker implements Listener {

    private final SecureAuthPlugin plugin;

    // Các command thuộc DangerousCommandListener — không xử lý ở đây
    private static final Set<String> DANGEROUS_CMDS = Set.of(
        "stop", "restart", "reload", "timings",
        "plugins", "pl", "version", "ver", "plugin", "plugman", "pman",
        "save-all", "save-off", "save-on", "unload", "whitelist",
        "execute", "minecraft:execute", "sudo"
    );

    public CommandBlocker(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    // ── Chặn khi chạy ────────────────────────────────────────────────────────

    @EventHandler(priority = EventPriority.NORMAL, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (!isEnabled()) return;

        Player player = event.getPlayer();

        // Chỉ áp dụng cho player đã login, không phải OP
        if (!plugin.getSessionManager().isAuthenticated(player.getUniqueId())) return;
        if (player.isOp()) return;

        String cmd = extractBase(event.getMessage());

        // Nhường DangerousCommandListener xử lý các server command
        if (DANGEROUS_CMDS.contains(cmd)) return;

        if (isBlocked(cmd)) {
            event.setCancelled(true);
            player.sendMessage(getBlockMessage());

            String ip = player.getAddress() != null
                    ? player.getAddress().getAddress().getHostAddress() : "unknown";
            plugin.getAuditLogger().log("CMD_BLOCKED",
                    player.getName(), player.getUniqueId().toString(), ip,
                    "Attempted blocked command: /" + cmd);
        }
    }

    // ── Ẩn khỏi tab-complete ─────────────────────────────────────────────────

    @EventHandler(priority = EventPriority.LOWEST)
    public void onCommandSend(PlayerCommandSendEvent event) {
        if (!isEnabled()) return;
        if (event.getPlayer().isOp()) return;

        Set<String> blocked = getBlockedSet();
        event.getCommands().removeIf(cmd -> {
            String base = cmd.toLowerCase(Locale.ROOT)
                    .replaceFirst("^[a-z0-9_]+:", "");
            return blocked.contains(base) || blocked.contains(cmd.toLowerCase(Locale.ROOT));
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private boolean isEnabled() {
        return plugin.getConfig().getBoolean("command-blocker.enabled", true);
    }

    private boolean isBlocked(String cmd) {
        return getBlockedSet().contains(cmd);
    }

    private Set<String> getBlockedSet() {
        List<String> list = plugin.getConfig().getStringList("command-blocker.blocked");
        Set<String> set = new HashSet<>();
        for (String entry : list) {
            String clean = entry.trim().toLowerCase(Locale.ROOT)
                    .replaceFirst("^/", "")
                    .replaceFirst("^[a-z0-9_]+:", "");
            if (!clean.isEmpty()) set.add(clean);
        }
        return set;
    }

    private String extractBase(String raw) {
        return raw.trim().toLowerCase(Locale.ROOT)
                .replaceFirst("^/", "")
                .split("\\s+")[0]
                .replaceFirst("^[a-z0-9_]+:", "");
    }

    private Component getBlockMessage() {
        String raw = plugin.getConfig().getString(
                "command-blocker.message", "&cUnknown command. Type /help for help.");
        return net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer
                .legacyAmpersand().deserialize(raw);
    }
}
