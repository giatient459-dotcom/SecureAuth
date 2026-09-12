package dev.tienday.secureauth.listener;

import dev.tienday.secureauth.SecureAuthPlugin;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.server.ServerCommandEvent;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * OPGuardListener — prevents privilege escalation via:
 *
 *  1. /op <player>  — granting OP status
 *  2. /deop <player> — removing OP (could be used to lock admins out)
 *  3. Permission-manager commands that grant secureauth.bypass:
 *       LuckPerms:  /lp user <x> permission set secureauth.bypass true
 *       PermissionsEx: /pex user <x> add secureauth.bypass
 *       GroupManager: /manuadd, /manpromote
 *       PowerRanks: /pr user setperm <x> secureauth.bypass
 *
 * Who can still use these:
 *  - Console (server owner) can always /op and manage perms freely
 *  - Players with secureauth.admin + secureauth.manage-op can /op via plugin
 *    BUT still cannot grant secureauth.bypass via permission managers
 *
 * Design rationale:
 *  A player who gains OP via /op (even by another OP) could immediately
 *  grant themselves secureauth.bypass and skip authentication entirely.
 *  This breaks the security model. The only safe approach is to block
 *  all in-game /op commands and route through /authadmin if needed.
 */
public class OPGuardListener implements Listener {

    private final SecureAuthPlugin plugin;

    // Commands that grant / modify OP status
    private static final Set<String> OP_COMMANDS = Set.of("op", "deop");

    // Pattern: detects any attempt to grant secureauth.bypass via permission plugins
    // Covers LuckPerms, PermissionsEx, GroupManager, PowerRanks, UltraPermissions
    private static final Pattern BYPASS_GRANT_PATTERN = Pattern.compile(
            "(?i).*(lp|luckperms|perm|pex|manuadd|manpromote|pr|ultraperms)\\s+.*secureauth\\.bypass.*"
    );

    // Also catch anyone trying to grant the bypass permission with vanilla:
    // Paper doesn't have /permission natively but plugins might expose it
    private static final Pattern VANILLA_BYPASS_PATTERN = Pattern.compile(
            "(?i)(permission|op)\\s+.*secureauth\\.bypass.*"
    );

    public OPGuardListener(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    // ── Player-issued commands ────────────────────────────────────────────────

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        String raw    = event.getMessage().trim();
        String lower  = raw.toLowerCase(Locale.ROOT);

        // Strip leading slash
        String noSlash = lower.startsWith("/") ? lower.substring(1) : lower;
        String cmdName = noSlash.split("\\s+")[0];

        // ── Block /op and /deop from players ────────────────────────────────
        if (OP_COMMANDS.contains(cmdName)
                && plugin.getConfigManager().isOpGuardBlockOpCommands()) {
            // Only allow if player has explicit manage-op permission
            if (!player.hasPermission("secureauth.manage-op")) {
                event.setCancelled(true);
                player.sendMessage(net.kyori.adventure.text.Component.text(
                        "§c[SecureAuth] Lệnh /op và /deop bị chặn. Liên hệ admin qua console.",
                        net.kyori.adventure.text.format.NamedTextColor.RED));
                auditAndLog(player, "OP_COMMAND_BLOCKED",
                        "Attempted: " + sanitize(raw));
                return;
            }
        }

        // ── Block permission-manager bypass grants ───────────────────────────
        if (plugin.getConfigManager().isOpGuardBlockBypassGrants()
                && containsBypassGrant(noSlash)) {
            event.setCancelled(true);
            player.sendMessage(net.kyori.adventure.text.Component.text(
                    "§c[SecureAuth] Không thể cấp secureauth.bypass qua lệnh này.",
                    net.kyori.adventure.text.format.NamedTextColor.RED));
            auditAndLog(player, "BYPASS_GRANT_BLOCKED",
                    "Attempted to grant secureauth.bypass: " + sanitize(raw));
        }
    }

    // ── Console-issued commands (allowed but still logged if suspicious) ──────

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = false)
    public void onConsoleCommand(ServerCommandEvent event) {
        if (!(event.getSender() instanceof ConsoleCommandSender)) return;

        String raw   = event.getCommand().trim().toLowerCase(Locale.ROOT);
        String cmd   = raw.split("\\s+")[0];

        // Console can do anything — but log OP grants and bypass grants for audit trail
        if (OP_COMMANDS.contains(cmd)) {
            plugin.getAuditLogger().logSystem("CONSOLE_OP_COMMAND",
                    "Console ran: " + sanitize(event.getCommand().trim()));
        } else if (containsBypassGrant(raw)) {
            plugin.getAuditLogger().logSystem("CONSOLE_BYPASS_GRANT",
                    "Console granted bypass: " + sanitize(event.getCommand().trim()));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private boolean containsBypassGrant(String lower) {
        return BYPASS_GRANT_PATTERN.matcher(lower).matches()
                || VANILLA_BYPASS_PATTERN.matcher(lower).matches();
    }

    private void auditAndLog(Player player, String eventType, String detail) {
        String ip = player.getAddress() != null
                ? player.getAddress().getAddress().getHostAddress() : "unknown";
        plugin.getAuditLogger().log(eventType, player.getName(),
                player.getUniqueId().toString(), ip, detail);
        plugin.getDatabaseManager().logEvent(
                player.getUniqueId().toString(), player.getName(), ip, eventType, detail);
        plugin.getLogger().warning("[SecureAuth][" + eventType + "] "
                + player.getName() + " (" + ip + "): " + detail);
    }

    private String sanitize(String s) {
        return s == null ? "" : s.replaceAll("[\r\n]", "_");
    }
}
