package dev.tienday.secureauth.listener;

import dev.tienday.secureauth.SecureAuthPlugin;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
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
 * với player không phải OP.
 *
 * Config (config.yml):
 *   command-blocker:
 *     enabled: true
 *     message: "&cKhông tìm thấy lệnh này."
 *     blocked:
 *       - "gamemode"
 *       - "tp"
 *       - ...
 */
public class CommandBlocker implements Listener {

    private final SecureAuthPlugin plugin;

    public CommandBlocker(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    // ── Chặn khi chạy ────────────────────────────────────────────────────────

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (!isEnabled()) return;

        Player player = event.getPlayer();
        if (player.isOp()) return;

        String cmd = extractBase(event.getMessage());
        if (isBlocked(cmd)) {
            event.setCancelled(true);
            player.sendMessage(getBlockMessage());

            // Log nếu suspicious (thử command bị chặn)
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
        // event.getCommands() là mutable set — remove trực tiếp
        event.getCommands().removeIf(cmd -> {
            String base = cmd.toLowerCase(Locale.ROOT)
                    .replaceFirst("^[a-z0-9_]+:", ""); // bỏ namespace (minecraft:tp → tp)
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
            // Normalize: bỏ slash, lowercase, bỏ namespace
            String clean = entry.trim().toLowerCase(Locale.ROOT)
                    .replaceFirst("^/", "")
                    .replaceFirst("^[a-z0-9_]+:", "");
            if (!clean.isEmpty()) set.add(clean);
        }
        return set;
    }

    private String extractBase(String raw) {
        // "/gamemode 1" → "gamemode", "/minecraft:tp" → "tp"
        String stripped = raw.trim().toLowerCase(Locale.ROOT)
                .replaceFirst("^/", "")
                .split("\\s+")[0]
                .replaceFirst("^[a-z0-9_]+:", "");
        return stripped;
    }

    private Component getBlockMessage() {
        String raw = plugin.getConfig().getString(
                "command-blocker.message", "&cKhông tìm thấy lệnh này.");
        return net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer
                .legacyAmpersand().deserialize(raw);
    }
}
