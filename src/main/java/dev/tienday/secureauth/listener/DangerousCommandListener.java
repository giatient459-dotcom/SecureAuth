package dev.tienday.secureauth.listener;

import dev.tienday.secureauth.SecureAuthPlugin;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * DangerousCommandListener — requires specific permissions for high-risk commands,
 * even for authenticated players.
 *
 * Command groups and their required permissions:
 *
 *   GROUP A — Server control         → secureauth.cmd.server-control
 *     /stop, /restart, /reload, /timings
 *
 *   GROUP B — Plugin management      → secureauth.cmd.plugin-manage
 *     /plugins, /pl, /version, /ver, /plugin, /plugman, /pman
 *
 *   GROUP C — World/chunk management → secureauth.cmd.world-manage
 *     /save-all, /save-off, /save-on, /unload, /whitelist
 *
 *   GROUP D — Console passthrough     → secureauth.cmd.console-exec
 *     /minecraft:execute, /execute with @a targets, /sudo (EssentialsX)
 *
 * None of these are granted to OP by default.
 * Server owner sets them explicitly in their permission plugin.
 *
 * Note: This listener fires AFTER AuthListener's command block,
 * so unauthenticated players are already handled.
 */
public class DangerousCommandListener implements Listener {

    private final SecureAuthPlugin plugin;

    // Map: command (lowercase, no slash) → required permission node
    private static final Map<String, String> COMMAND_PERMISSIONS = buildCommandMap();

    private static Map<String, String> buildCommandMap() {
        final String SERVER  = "secureauth.cmd.server-control";
        final String PLUGIN  = "secureauth.cmd.plugin-manage";
        final String WORLD   = "secureauth.cmd.world-manage";
        final String CONSOLE = "secureauth.cmd.console-exec";

        return Map.ofEntries(
            // Group A: Server control
            Map.entry("stop",            SERVER),
            Map.entry("restart",         SERVER),
            Map.entry("reload",          SERVER),
            Map.entry("timings",         SERVER),

            // Group B: Plugin management
            Map.entry("plugins",         PLUGIN),
            Map.entry("pl",              PLUGIN),
            Map.entry("version",         PLUGIN),
            Map.entry("ver",             PLUGIN),
            Map.entry("plugin",          PLUGIN),
            Map.entry("plugman",         PLUGIN),
            Map.entry("pman",            PLUGIN),

            // Group C: World/chunk management
            Map.entry("save-all",        WORLD),
            Map.entry("save-off",        WORLD),
            Map.entry("save-on",         WORLD),
            Map.entry("unload",          WORLD),
            Map.entry("whitelist",       WORLD),

            // Group D: Console-level execution
            Map.entry("execute",         CONSOLE),
            Map.entry("minecraft:execute", CONSOLE),
            Map.entry("sudo",            CONSOLE)
        );
    }

    // Commands never blocked regardless of login state (handled by AuthListener already)
    private static final Set<String> AUTH_COMMANDS = Set.of("login", "register", "link");

    public DangerousCommandListener(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOW, ignoreCancelled = false)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        String raw    = event.getMessage().trim();
        String lower  = raw.toLowerCase(Locale.ROOT);
        String noSlash = lower.startsWith("/") ? lower.substring(1) : lower;

        // Split off subcommands/arguments to get base command
        String cmdName = noSlash.split("\\s+")[0];

        // Auth commands: always allow (AuthListener handles pre-login blocking)
        if (AUTH_COMMANDS.contains(cmdName)) return;

        // Feature kill-switch
        if (!plugin.getConfigManager().isDangerousCommandsEnabled()) return;

        // Console-only commands — block from ALL players regardless of permission
        java.util.List<String> consoleOnly = plugin.getConfigManager().getConsoleOnlyCommands();
        if (consoleOnly.contains(cmdName)) {
            event.setCancelled(true);
            player.sendMessage(net.kyori.adventure.text.Component.text(
                    "§c[SecureAuth] Lệnh này chỉ chạy được từ console.",
                    net.kyori.adventure.text.format.NamedTextColor.RED));
            String ip = player.getAddress() != null
                    ? player.getAddress().getAddress().getHostAddress() : "unknown";
            String detail = "Attempted console-only command: /" + sanitize(cmdName);
            plugin.getAuditLogger().log("CONSOLE_ONLY_BLOCKED",
                    player.getName(), player.getUniqueId().toString(), ip, detail);
            plugin.getDatabaseManager().logEvent(
                    player.getUniqueId().toString(), player.getName(), ip,
                    "CONSOLE_ONLY_BLOCKED", detail);
            plugin.getLogger().warning("[SecureAuth][CONSOLE_ONLY_BLOCKED] "
                    + player.getName() + " (" + ip + "): " + detail);
            return;
        }

        // Check if this command is in the dangerous map
        String requiredPerm = COMMAND_PERMISSIONS.get(cmdName);

        // Also check extra-protected commands from config (all require server-control perm)
        if (requiredPerm == null) {
            java.util.List<String> extra = plugin.getConfigManager().getDangerousCommandsExtra();
            if (extra.contains(cmdName)) {
                requiredPerm = "secureauth.cmd.server-control";
            }
        }

        if (requiredPerm == null) return; // Not a restricted command

        // Player must be authenticated first (AuthListener ensures this,
        // but double-check for defense in depth)
        if (!plugin.getSessionManager().isAuthenticated(player.getUniqueId())) {
            event.setCancelled(true);
            player.sendMessage(plugin.getConfigManager().getMessage("not-logged-in"));
            return;
        }

        // Check specific permission
        if (!player.hasPermission(requiredPerm)) {
            event.setCancelled(true);
            player.sendMessage(net.kyori.adventure.text.Component.text(
                    "§c[SecureAuth] Bạn không có quyền dùng lệnh này. Yêu cầu: §e" + requiredPerm,
                    net.kyori.adventure.text.format.NamedTextColor.RED));

            String ip = player.getAddress() != null
                    ? player.getAddress().getAddress().getHostAddress() : "unknown";
            String detail = "Attempted /" + sanitize(cmdName) + " without " + requiredPerm;

            plugin.getAuditLogger().log("DANGEROUS_CMD_BLOCKED",
                    player.getName(), player.getUniqueId().toString(), ip, detail);
            plugin.getDatabaseManager().logEvent(
                    player.getUniqueId().toString(), player.getName(), ip,
                    "DANGEROUS_CMD_BLOCKED", detail);
            plugin.getLogger().warning("[SecureAuth][DANGEROUS_CMD_BLOCKED] "
                    + player.getName() + " (" + ip + "): " + detail);
        }
    }

    private String sanitize(String s) {
        return s == null ? "" : s.replaceAll("[\r\n]", "_");
    }
}
