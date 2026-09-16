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
        long timeoutMs = plugin.getConfigManager().getSessionTimeout() * 1000L;

        List<UUID> toKick = new ArrayList<>();
        for (Map.Entry<UUID, Long> entry : sessions.entrySet()) {
            UUID uuid = entry.getKey();
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
    }

    public void setAwaitingTwoFa(UUID uuid) {
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

    public void touch(UUID uuid) {
        if (sessions.containsKey(uuid)) {
            sessions.put(uuid, System.currentTimeMillis());
        }
    }

    public void invalidate(UUID uuid) {
        sessions.remove(uuid);
        awaitingTwoFa.remove(uuid);
        preLoginLocations.remove(uuid);
    }

    // ---- Pre-login location ----

    /** Lưu vị trí player đứng lúc join (trước khi bị teleport vào End). */
    public void savePreLoginLocation(UUID uuid, Location loc) {
        if (uuid == null || loc == null) return;
        preLoginLocations.put(uuid, loc.clone());
    }

    /** Lấy vị trí đã lưu. Trả về null nếu chưa có. */
    public Location getPreLoginLocation(UUID uuid) {
        if (uuid == null) return null;
        Location loc = preLoginLocations.get(uuid);
        return loc == null ? null : loc.clone();
    }

    /** Xoá vị trí đã lưu (gọi sau khi restore xong). */
    public void clearPreLoginLocation(UUID uuid) {
        if (uuid != null) preLoginLocations.remove(uuid);
    }

    public void shutdown() {
        if (timeoutTask != null) {
            timeoutTask.cancel();
            timeoutTask = null;
        }
        sessions.clear();
        awaitingTwoFa.clear();
        preLoginLocations.clear();
    }
}
