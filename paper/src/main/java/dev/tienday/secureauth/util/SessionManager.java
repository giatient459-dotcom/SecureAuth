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

/**
 * In-memory auth sessions.
 * Optional IP binding (security.bind-session-ip) mitigates session reuse after IP change.
 */
public class SessionManager {

    private record Session(long lastActive, String ip) {}

    private final SecureAuthPlugin plugin;

    private final Map<UUID, Session> sessions = new ConcurrentHashMap<>();
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
        long timeoutMs = plugin.getConfigManager().getSessionTimeout() * 1000L;

        List<UUID> toKick = new ArrayList<>();
        for (Map.Entry<UUID, Session> entry : sessions.entrySet()) {
            UUID uuid = entry.getKey();
            Session s = entry.getValue();
            if (s == null) continue;
            if (now - s.lastActive() <= timeoutMs) continue;
            if (sessions.remove(uuid, s)) {
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
        authenticate(uuid, null);
    }

    public void authenticate(UUID uuid, String ip) {
        String bound = (ip == null || ip.isBlank() || "unknown".equals(ip)) ? null : ip;
        sessions.put(uuid, new Session(System.currentTimeMillis(), bound));
        awaitingTwoFa.remove(uuid);
        int grace = plugin.getConfigManager().getLoginGraceSeconds();
        if (grace > 0) {
            graceUntil.put(uuid, System.currentTimeMillis() + grace * 1000L);
        }
    }

    public void setAwaitingTwoFa(UUID uuid) {
        awaitingTwoFa.add(uuid);
        sessions.put(uuid, new Session(System.currentTimeMillis(), null));
    }

    public boolean isAwaitingTwoFa(UUID uuid) {
        return awaitingTwoFa.contains(uuid);
    }

    public boolean isAuthenticated(UUID uuid) {
        if (awaitingTwoFa.contains(uuid)) return false;
        return sessions.containsKey(uuid);
    }

    /**
     * Authenticated + optional IP match (when security.bind-session-ip=true).
     * Mismatch → invalidate (anti session-hijack / IP swap).
     */
    public boolean isAuthenticated(Player player) {
        if (player == null) return false;
        UUID uuid = player.getUniqueId();
        if (awaitingTwoFa.contains(uuid)) return false;
        Session s = sessions.get(uuid);
        if (s == null) return false;
        if (!isBindSessionIp()) return true;
        String cur = playerIp(player);
        if (s.ip() == null || s.ip().isBlank()) {
            // bind on first successful check after login without IP
            sessions.put(uuid, new Session(s.lastActive(), cur));
            return true;
        }
        if (!s.ip().equals(cur)) {
            plugin.getLogger().warning("[SecureAuth] Session IP mismatch for "
                    + player.getName() + " bound=" + s.ip() + " now=" + cur + " — invalidating");
            invalidate(uuid);
            return false;
        }
        return true;
    }

    private boolean isBindSessionIp() {
        return plugin.getConfig().getBoolean("security.bind-session-ip", true);
    }

    private static String playerIp(Player player) {
        try {
            if (player.getAddress() != null && player.getAddress().getAddress() != null) {
                return player.getAddress().getAddress().getHostAddress();
            }
        } catch (Exception ignored) {}
        return "unknown";
    }

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
        Session s = sessions.get(uuid);
        if (s != null) {
            sessions.put(uuid, new Session(System.currentTimeMillis(), s.ip()));
        }
    }

    public void invalidate(UUID uuid) {
        sessions.remove(uuid);
        awaitingTwoFa.remove(uuid);
        preLoginLocations.remove(uuid);
        graceUntil.remove(uuid);
    }

    public void savePreLoginLocation(UUID uuid, Location loc) {
        preLoginLocations.put(uuid, loc.clone());
    }

    public void restoreLocationAfterLogin(Player player) {
        Location saved = preLoginLocations.remove(player.getUniqueId());
        String loginWorld = plugin.getConfigManager().getLoginSpawnWorldName();
        org.bukkit.Location authSpawn = plugin.getConfigManager().getLoginSpawnLocation();

        if (saved != null && saved.getWorld() != null) {
            if (authSpawn != null
                    && saved.getWorld().equals(authSpawn.getWorld())
                    && saved.distanceSquared(authSpawn) < 4.0) {
                if (!plugin.getServer().getWorlds().isEmpty()) {
                    org.bukkit.World def = plugin.getServer().getWorlds().get(0);
                    if (def != null) player.teleport(def.getSpawnLocation());
                }
                return;
            }
            player.teleport(saved);
            return;
        }

        if (!loginWorld.isEmpty()
                && player.getWorld() != null
                && player.getWorld().getName().equals(loginWorld)
                && !plugin.getServer().getWorlds().isEmpty()) {
            org.bukkit.World def = plugin.getServer().getWorlds().get(0);
            if (def != null
                    && (loginWorld.isEmpty() || !def.getName().equals(loginWorld))) {
                player.teleport(def.getSpawnLocation());
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
