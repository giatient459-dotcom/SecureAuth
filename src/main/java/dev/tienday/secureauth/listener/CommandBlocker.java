package dev.tienday.secureauth.listener;

import dev.tienday.secureauth.SecureAuthPlugin;
import net.kyori.adventure.text.Component;
import org.bukkit.command.Command;
import org.bukkit.command.PluginIdentifiableCommand;
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
 *
 * FIX:
 *  - Resolve alias qua CommandMap: nếu "gamemode" bị block thì "/gm", "/gmc"
 *    cũng bị block (trước đây chỉ block đúng literal trong config).
 *  - Cache blocked set: không tạo HashSet mới mỗi event (perf).
 *  - Public reload() để gọi khi config được reload runtime.
 */
public class CommandBlocker implements Listener {

    private final SecureAuthPlugin plugin;

    /** Cache blocked set — FIX: tránh tạo HashSet mỗi event. */
    private volatile Set<String> cachedBlocked = null;

    public CommandBlocker(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    /** FIX: gọi khi config thay đổi runtime để refresh cache. */
    public void reload() {
        this.cachedBlocked = null;
    }

    // ── Chặn khi chạy ────────────────────────────────────────────────────────

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (!isEnabled()) return;

        Player player = event.getPlayer();
        if (player.isOp()) return;

        String cmd = extractBase(event.getMessage());
        if (isBlockedResolved(cmd)) {
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
            String base = normalize(cmd);
            if (blocked.contains(base)) return true;
            // FIX: check alias của command này.
            return isCommandOrAliasBlocked(base, blocked);
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private boolean isEnabled() {
        return plugin.getConfig().getBoolean("command-blocker.enabled", true);
    }

    /**
     * FIX: kiểm tra command có bị block không, bao gồm cả alias.
     * Ví dụ: "gamemode" bị block → "/gm", "/gmc" cũng bị block.
     */
    private boolean isBlockedResolved(String cmd) {
        Set<String> blocked = getBlockedSet();
        if (blocked.contains(cmd)) return true;
        return isCommandOrAliasBlocked(cmd, blocked);
    }

    private boolean isCommandOrAliasBlocked(String name, Set<String> blocked) {
        Command bukkitCmd = plugin.getServer().getCommandMap().getCommand(name);
        if (bukkitCmd == null) return false;

        // Check canonical name
        String canonical = bukkitCmd.getName().toLowerCase(Locale.ROOT);
        if (blocked.contains(canonical)) return true;

        // Check aliases
        for (String alias : bukkitCmd.getAliases()) {
            if (blocked.contains(alias.toLowerCase(Locale.ROOT))) return true;
        }

        // Check plugin prefix (nếu là PluginCommand có thể có prefix)
        if (bukkitCmd instanceof PluginIdentifiableCommand pic) {
            String pluginName = pic.getPlugin().getName().toLowerCase(Locale.ROOT);
            if (blocked.contains(pluginName + ":" + canonical)) return true;
        }

        return false;
    }

    /** FIX: cache — tạo set một lần duy nhất cho đến khi reload(). */
    private Set<String> getBlockedSet() {
        Set<String> cached = cachedBlocked;
        if (cached != null) return cached;

        synchronized (this) {
            if (cachedBlocked != null) return cachedBlocked;

            List<String> list = plugin.getConfig().getStringList("command-blocker.blocked");
            Set<String> set = new HashSet<>();
            for (String entry : list) {
                if (entry == null) continue;
                String clean = normalize(entry);
                if (!clean.isEmpty()) set.add(clean);
            }
            cachedBlocked = set;
            return set;
        }
    }

    private String normalize(String raw) {
        return raw.trim().toLowerCase(Locale.ROOT)
                .replaceFirst("^/", "")
                .replaceFirst("^[a-z0-9_]+:", "");
    }

    private String extractBase(String raw) {
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
