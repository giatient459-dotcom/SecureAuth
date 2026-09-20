package dev.tienday.secureauth.listener;

import dev.tienday.secureauth.SecureAuthPlugin;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.server.ServerCommandEvent;
import org.bukkit.event.server.ServerLoadEvent;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * OPGuardListener — chặn toàn bộ các vector leo thang đặc quyền:
 *
 *  1. /op, /deop từ player
 *  2. Essentials/CMI alias: /essentials:op, /minecraft:op, ...
 *  3. Permission-manager commands cấp secureauth.bypass
 *  4. Tự động deop player khi join nếu OP nhưng không có secureauth.manage-op
 *  5. Tự động xóa OP khi được cấp qua console (nếu config yêu cầu)
 *
 * Console luôn được phép — nhưng mọi hành động đều được audit log.
 */
public class OPGuardListener implements Listener {

    private final SecureAuthPlugin plugin;

    // Tất cả alias của /op và /deop kể cả namespace
    private static final Set<String> OP_COMMAND_ALIASES = Set.of(
        "op", "deop",
        "minecraft:op", "minecraft:deop",
        "bukkit:op", "bukkit:deop"
    );

    // Essentials và plugin khác có thể expose /op dưới tên khác
    private static final Pattern OP_ALIAS_PATTERN = Pattern.compile(
        "(?i)^([a-z0-9_]+:)?de?op(\\s+.*)?$"
    );

    // Chặn cấp secureauth.bypass qua LuckPerms, PEX, GroupManager, v.v.
    private static final Pattern BYPASS_GRANT_PATTERN = Pattern.compile(
        "(?i)(lp|luckperms|pex|permissionsex|perm|manuadd|manpromote|manaddp" +
        "|ultraperms|upp|powerranks|pr)\\s+.*secureauth[._]bypass.*"
    );

    // Chặn /sudo <player> /op hoặc /sudo <player> op
    private static final Pattern SUDO_OP_PATTERN = Pattern.compile(
        "(?i)(sudo|esudo|runas)\\s+\\S+\\s+(/?de?op|minecraft:de?op).*"
    );

    public OPGuardListener(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    // ── Tự động deop player khi join nếu không được phép ────────────────────

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerJoin(org.bukkit.event.player.PlayerJoinEvent event) {
        Player player = event.getPlayer();
        if (!player.isOp()) return;
        if (player.hasPermission("secureauth.manage-op")) return;

        // Player có OP nhưng không có secureauth.manage-op → deop ngay
        player.setOp(false);
        plugin.getAuditLogger().log("AUTO_DEOP_ON_JOIN",
                player.getName(), player.getUniqueId().toString(),
                safeIp(player),
                "Player had OP without secureauth.manage-op — auto-deoped");
        plugin.getLogger().warning("[SecureAuth][AUTO_DEOP] " + player.getName()
                + " was deoped on join (no secureauth.manage-op)");
    }

    // ── Chặn /op và alias từ player ──────────────────────────────────────────

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        if (!plugin.getConfigManager().isOpGuardBlockOpCommands()) return;

        Player player = event.getPlayer();
        String raw    = event.getMessage().trim();
        String noSlash = raw.startsWith("/") ? raw.substring(1) : raw;
        String lower  = noSlash.toLowerCase(Locale.ROOT);
        String cmdName = lower.split("\\s+")[0];

        // Chặn /op, /deop và mọi namespace alias
        boolean isOpCmd = OP_COMMAND_ALIASES.contains(cmdName)
                || OP_ALIAS_PATTERN.matcher(noSlash).matches();

        if (isOpCmd) {
            if (!player.hasPermission("secureauth.manage-op")) {
                event.setCancelled(true);
                player.sendMessage(net.kyori.adventure.text.Component.text(
                        "§c[SecureAuth] /op và /deop bị chặn. Dùng console.",
                        net.kyori.adventure.text.format.NamedTextColor.RED));
                auditAndLog(player, "OP_CMD_BLOCKED", "Attempted: " + sanitize(raw));
                return;
            }
        }

        // Chặn /sudo <player> /op
        if (SUDO_OP_PATTERN.matcher(lower).matches()) {
            event.setCancelled(true);
            player.sendMessage(net.kyori.adventure.text.Component.text(
                    "§c[SecureAuth] Không thể sudo lệnh op.",
                    net.kyori.adventure.text.format.NamedTextColor.RED));
            auditAndLog(player, "SUDO_OP_BLOCKED", "Attempted sudo-op: " + sanitize(raw));
            return;
        }

        // Chặn cấp secureauth.bypass qua permission plugin
        if (plugin.getConfigManager().isOpGuardBlockBypassGrants()
                && BYPASS_GRANT_PATTERN.matcher(lower).find()) {
            event.setCancelled(true);
            player.sendMessage(net.kyori.adventure.text.Component.text(
                    "§c[SecureAuth] Không thể cấp secureauth.bypass.",
                    net.kyori.adventure.text.format.NamedTextColor.RED));
            auditAndLog(player, "BYPASS_GRANT_BLOCKED", "Attempted: " + sanitize(raw));
        }
    }

    // ── Console — cho phép nhưng audit log ───────────────────────────────────

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = false)
    public void onConsoleCommand(ServerCommandEvent event) {
        if (!(event.getSender() instanceof ConsoleCommandSender)) return;

        String raw   = event.getCommand().trim();
        String lower = raw.toLowerCase(Locale.ROOT);
        String cmd   = lower.split("\\s+")[0];

        boolean isOpCmd = OP_COMMAND_ALIASES.contains(cmd)
                || OP_ALIAS_PATTERN.matcher(lower).matches();

        if (isOpCmd) {
            plugin.getAuditLogger().logSystem("CONSOLE_OP_CMD",
                    "Console ran: " + sanitize(raw));
            plugin.getLogger().warning("[SecureAuth][CONSOLE_OP] Console ran: " + sanitize(raw));
        } else if (BYPASS_GRANT_PATTERN.matcher(lower).find()) {
            plugin.getAuditLogger().logSystem("CONSOLE_BYPASS_GRANT",
                    "Console granted bypass: " + sanitize(raw));
            plugin.getLogger().warning("[SecureAuth][CONSOLE_BYPASS] " + sanitize(raw));
        } else if (SUDO_OP_PATTERN.matcher(lower).matches()) {
            plugin.getAuditLogger().logSystem("CONSOLE_SUDO_OP",
                    "Console sudo-op: " + sanitize(raw));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void auditAndLog(Player player, String eventType, String detail) {
        String ip = safeIp(player);
        plugin.getAuditLogger().log(eventType, player.getName(),
                player.getUniqueId().toString(), ip, detail);
        plugin.getDatabaseManager().logEvent(
                player.getUniqueId().toString(), player.getName(),
                ip, eventType, detail);
        plugin.getLogger().warning("[SecureAuth][" + eventType + "] "
                + player.getName() + " (" + ip + "): " + detail);
    }

    private static String safeIp(Player player) {
        try {
            if (player.getAddress() != null && player.getAddress().getAddress() != null)
                return player.getAddress().getAddress().getHostAddress();
        } catch (Exception ignored) {}
        return "unknown";
    }

    private String sanitize(String s) {
        return s == null ? "" : s.replaceAll("[\r\n]", "_");
    }
}
