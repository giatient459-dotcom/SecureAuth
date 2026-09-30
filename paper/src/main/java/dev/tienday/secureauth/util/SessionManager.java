package dev.tienday.secureauth.util;

import dev.tienday.secureauth.SecureAuthPlugin;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitTask;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {

    private final SecureAuthPlugin plugin;

    private final Map<UUID, Long> sessions = new ConcurrentHashMap<>();
    private final Map<UUID, Location> preLoginLocations = new ConcurrentHashMap<>();
    private final Set<UUID> awaitingTwoFa = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Long> graceUntil = new ConcurrentHashMap<>();

    private BukkitTask timeoutTask;

    public SessionManager(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public void startTimeoutTask() {
        int intervalSec = 30;
        timeoutTask = plugin.getServer().getScheduler().runTaskTimer(
                plugin, this::runTimeoutCheck, 20L * intervalSec, 20L * intervalSec);
    }

    private void runTimeoutCheck() {
        long now = System.currentTimeMillis();
        int idleSec = plugin.getConfigManager().getAuthIdleTimeout();
        if (idleSec <= 0) return; // 0 = không kick AFK
        long timeoutMs = idleSec * 1000L;

        List<UUID> toKick = new ArrayList<>();
        for (Map.Entry<UUID, Long> entry : sessions.entrySet()) {
            UUID uuid = entry.getKey();
            if (awaitingTwoFa.contains(uuid)) continue;
            Long lastActive = entry.getValue();
            if (lastActive == null) continue;
            if (now - lastActive <= timeoutMs) continue;

            if (sessions.remove(uuid, lastActive)) {
                awaitingTwoFa.remove(uuid);
                toKick.add(uuid);
            }
        }

        for (UUID uuid : toKick) {
            Player p = plugin.getServer().getPlayer(uuid);
            if (p != null && p.isOnline()) {
                p.kick(plugin.getConfigManager().getMessageNoPrefix("kick-session-expired"));
            }
        }
    }

    public void authenticate(UUID uuid) {
        sessions.put(uuid, System.currentTimeMillis());
        awaitingTwoFa.remove(uuid);
        int grace = plugin.getConfigManager().getLoginGraceSeconds();
        if (grace > 0) {
            graceUntil.put(uuid, System.currentTimeMillis() + grace * 1000L);
        }
    }

    public void setAwaitingTwoFa(UUID uuid) {
        // Set the awaiting flag BEFORE writing the session entry so that
        // isAuthenticated() never observes (session=present, awaiting=absent).
        awaitingTwoFa.add(uuid);
        sessions.put(uuid, System.currentTimeMillis());
    }

    public boolean isAwaitingTwoFa(UUID uuid) {
        return awaitingTwoFa.contains(uuid);
    }

    public boolean isAuthenticated(UUID uuid) {
        if (awaitingTwoFa.contains(uuid)) return false;
        return sessions.containsKey(uuid);
    }

    /** True for a few seconds after login — softens teleport/kick races. */
    public boolean isInGrace(UUID uuid) {
        Long until = graceUntil.get(uuid);
        if (until == null) return false;
        if (System.currentTimeMillis() > until) {
            graceUntil.remove(uuid, until);
            return false;
        }
        return true;
    }

    public void touch(UUID uuid) {
        if (sessions.containsKey(uuid)) {
            sessions.put(uuid, System.currentTimeMillis());
        }
    }

    public void invalidate(UUID uuid) {
        sessions.remove(uuid);
        awaitingTwoFa.remove(uuid);
        preLoginLocations.remove(uuid);
        graceUntil.remove(uuid);
    }

    /** Lưu vị trí thật trước khi tp đến End lobby */
    public void savePreLoginLocation(UUID uuid, Location loc) {
        preLoginLocations.put(uuid, loc.clone());
    }

    /**
     * Restore vị trí thật sau khi login thành công.
     * Nếu không có vị trí lưu (lần đầu join) → giữ nguyên spawn.
     */
    public void restoreLocationAfterLogin(Player player) {
        Location saved = preLoginLocations.remove(player.getUniqueId());
        String loginWorld = plugin.getConfigManager().getLoginSpawnWorldName();

        if (saved != null && saved.getWorld() != null) {
            // Nếu vị trí join khác login-lobby → restore chỗ thật
            if (loginWorld.isEmpty() || !saved.getWorld().getName().equals(loginWorld)) {
                player.teleport(saved);
                return;
            }
        }
        // Join lần đầu / chỉ đứng trong login-lobby → world đầu tiên (hoặc giữ nguyên)
        if (!plugin.getServer().getWorlds().isEmpty()) {
            org.bukkit.World defaultWorld = plugin.getServer().getWorlds().get(0);
            if (defaultWorld != null
                    && (player.getWorld() == null
                    || (!loginWorld.isEmpty() && player.getWorld().getName().equals(loginWorld)))) {
                player.teleport(defaultWorld.getSpawnLocation());
            }
        }
    }

    public void shutdown() {
        if (timeoutTask != null) {
            timeoutTask.cancel();
            timeoutTask = null;
        }
        sessions.clear();
        awaitingTwoFa.clear();
        preLoginLocations.clear();
        graceUntil.clear();
    }
}
