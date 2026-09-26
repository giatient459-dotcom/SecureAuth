package dev.tienday.secureauth.listener;

import dev.tienday.secureauth.SecureAuthPlugin;
import io.papermc.paper.event.player.AsyncChatEvent;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityTargetEvent;
import org.bukkit.event.entity.FoodLevelChangeEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.PlayerAttemptPickupItemEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractAtEntityEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerCommandSendEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.scheduler.BukkitRunnable;

import java.util.Locale;
import java.util.Set;
import java.util.UUID;

public class AuthListener implements Listener {

    private static final Set<String> ALLOWED_COMMANDS = Set.of(
            "login", "l", "register", "reg", "link",
            "changepassword", "changepass", "cpw", "uuid"
    );

    private final SecureAuthPlugin plugin;

    public AuthListener(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    // ---- Join / Quit ----

    @EventHandler(priority = EventPriority.LOWEST)
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();

        // Clear any stale state.
        plugin.getSessionManager().invalidate(uuid);
        plugin.getTwoFactorManager().clearCode(uuid);

        // Hide the fresh (unauthenticated) player from everyone, and everyone from them.
        applyInitialVanish(player);

        // Lưu vị trí thật NGAY (tick 0) trước khi bất kỳ teleport nào xảy ra
        plugin.getSessionManager().savePreLoginLocation(uuid, player.getLocation());

        // Teleport đến The End lobby trước khi login
        new BukkitRunnable() {
            @Override
            public void run() {
                if (!player.isOnline()) return;
                if (plugin.getSessionManager().isAuthenticated(uuid)) return;

                // Lấy world The End (tên mặc định: world_the_end)
                String endWorldName = plugin.getConfig().getString("login-world.end-world", "world_the_end");
                org.bukkit.World endWorld = plugin.getServer().getWorld(endWorldName);

                if (endWorld != null) {
                    double x = plugin.getConfig().getDouble("login-world.x", 0.5);
                    double y = plugin.getConfig().getDouble("login-world.y", 64);
                    double z = plugin.getConfig().getDouble("login-world.z", 0.5);
                    float yaw   = (float) plugin.getConfig().getDouble("login-world.yaw", 0);
                    float pitch = (float) plugin.getConfig().getDouble("login-world.pitch", 0);
                    player.teleport(new org.bukkit.Location(endWorld, x, y, z, yaw, pitch));
                } else {
                    plugin.getLogger().warning("[SecureAuth] Login world '" + endWorldName
                            + "' not found! Check login-world.end-world in config.yml");
                }
            }
        }.runTaskLater(plugin, 5L); // 5 tick — đủ để client load xong

        // Deferred: send the correct prompt after the client is loaded.
        new BukkitRunnable() {
            @Override
            public void run() {
                if (!player.isOnline()) return;
                if (plugin.getSessionManager().isAuthenticated(uuid)) return;

                plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> {
                    boolean registered = plugin.getDatabaseManager().isRegistered(uuid.toString());
                    plugin.getServer().getScheduler().runTask(plugin, () -> {
                        if (!player.isOnline()) return;
                        if (plugin.getSessionManager().isAuthenticated(uuid)) return;
                        if (registered) {
                            player.sendMessage(plugin.getConfigManager().getMessage("not-logged-in"));
                        } else {
                            player.sendMessage(plugin.getConfigManager().getMessage("not-registered"));
                        }
                    });
                });
            }
        }.runTaskLater(plugin, 20L);

        long timeoutTicks = plugin.getConfigManager().getSessionTimeout() * 20L;
        new BukkitRunnable() {
            @Override
            public void run() {
                if (player.isOnline() && !plugin.getSessionManager().isAuthenticated(uuid)) {
                    player.kick(plugin.getConfigManager().getMessageNoPrefix("kick-not-logged-in"));
                }
            }
        }.runTaskLater(plugin, timeoutTicks);
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onQuit(PlayerQuitEvent event) {
        UUID uuid = event.getPlayer().getUniqueId();
        plugin.getSessionManager().invalidate(uuid);
        plugin.getTwoFactorManager().clearCode(uuid);
        // Token buckets only — login lockout intentionally kept
        plugin.getRateLimiter().clearPlayerEphemeral(uuid.toString());
    }

    /** Hide tab-complete for unauthenticated players except auth commands. */
    @EventHandler(priority = EventPriority.LOWEST)
    public void onCommandSend(PlayerCommandSendEvent event) {
        if (plugin.getSessionManager().isAuthenticated(event.getPlayer().getUniqueId())) {
            return;
        }
        event.getCommands().removeIf(cmd -> {
            if (cmd == null) return true;
            String c = cmd.toLowerCase(java.util.Locale.ROOT);
            int colon = c.indexOf(':');
            if (colon >= 0 && colon + 1 < c.length()) c = c.substring(colon + 1);
            return !ALLOWED_COMMANDS.contains(c);
        });
    }

    // ---- Vanish ----

    /**
     * Unauthenticated player should not be visible to / see anyone on join.
     */
    private void applyInitialVanish(Player unauthed) {
        for (Player other : plugin.getServer().getOnlinePlayers()) {
            if (other.equals(unauthed)) continue;
            other.hidePlayer(plugin, unauthed);
            unauthed.hidePlayer(plugin, other);
        }
    }

    /**
     * Called on the main thread once a player finishes authentication.
     */
    public static void revealPlayer(SecureAuthPlugin plugin, Player authed) {
        for (Player other : plugin.getServer().getOnlinePlayers()) {
            if (other.equals(authed)) continue;
            boolean otherAuthed = plugin.getSessionManager().isAuthenticated(other.getUniqueId());
            if (otherAuthed) {
                other.showPlayer(plugin, authed);
                authed.showPlayer(plugin, other);
            } else {
                other.hidePlayer(plugin, authed);
                authed.hidePlayer(plugin, other);
            }
        }
    }

    // ---- Blocking ----

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onMove(PlayerMoveEvent event) {
        if (isBlocked(event.getPlayer())) {
            if (event.getFrom().getBlockX() != event.getTo().getBlockX()
                    || event.getFrom().getBlockY() != event.getTo().getBlockY()
                    || event.getFrom().getBlockZ() != event.getTo().getBlockZ()) {
                event.setCancelled(true);
            }
        } else {
            plugin.getSessionManager().touch(event.getPlayer().getUniqueId());
        }
    }

    // 1.19+ Paper: dùng AsyncChatEvent (Adventure API)
    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onChat(AsyncChatEvent event) {
        if (isBlocked(event.getPlayer())) {
            event.setCancelled(true);
            event.getPlayer().sendMessage(plugin.getConfigManager().getMessage("not-logged-in"));
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        if (!isBlocked(player)) {
            plugin.getSessionManager().touch(player.getUniqueId());
            return;
        }

        String cmd = normalizeCommand(event.getMessage());
        if (cmd != null && ALLOWED_COMMANDS.contains(cmd)) {
            return;
        }

        event.setCancelled(true);
        player.sendMessage(plugin.getConfigManager().getMessage("not-logged-in"));
    }

    /** Strip leading /, namespace (minecraft:op → op), Locale.ROOT lower-case. */
    static String normalizeCommand(String message) {
        if (message == null) return null;
        String raw = message.trim().toLowerCase(Locale.ROOT);
        while (raw.startsWith("/")) raw = raw.substring(1);
        if (raw.isEmpty()) return null;
        String first = raw.split("\s+")[0];
        int colon = first.indexOf(':');
        if (colon >= 0 && colon + 1 < first.length()) {
            first = first.substring(colon + 1);
        }
        return first;
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onBlockBreak(BlockBreakEvent event) {
        if (isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onBlockPlace(BlockPlaceEvent event) {
        if (isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onInventoryOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player p && isBlocked(p)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player p && isBlocked(p)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onInteract(PlayerInteractEvent event) {
        if (isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onInteractEntity(PlayerInteractEntityEvent event) {
        if (isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onInteractAtEntity(PlayerInteractAtEntityEvent event) {
        if (isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof Player p && isBlocked(p)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onDamageByEntity(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player p && isBlocked(p)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onFoodLevel(FoodLevelChangeEvent event) {
        if (event.getEntity() instanceof Player p && isBlocked(p)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onItemDrop(PlayerDropItemEvent event) {
        if (isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onItemPickup(PlayerAttemptPickupItemEvent event) {
        if (isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onEntityTarget(EntityTargetEvent event) {
        if (event.getTarget() instanceof Player p && isBlocked(p)) {
            event.setCancelled(true);
        }
    }

    // ---- Helper ----

    private boolean isBlocked(Player player) {
        if (player.hasPermission("secureauth.bypass")) return false;
        return !plugin.getSessionManager().isAuthenticated(player.getUniqueId());
    }
}
