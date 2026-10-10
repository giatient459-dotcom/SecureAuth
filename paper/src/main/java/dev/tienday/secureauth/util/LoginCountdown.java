package dev.tienday.secureauth.util;

import dev.tienday.secureauth.SecureAuthPlugin;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitRunnable;
import org.bukkit.scheduler.BukkitTask;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Action-bar countdown before kicking unauthenticated players. */
public final class LoginCountdown {

    private final SecureAuthPlugin plugin;
    private final Map<UUID, BukkitTask> tasks = new ConcurrentHashMap<>();

    public LoginCountdown(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public void start(Player player) {
        if (!plugin.getConfig().getBoolean("security.login-countdown-actionbar", true)) return;
        stop(player.getUniqueId());
        UUID uuid = player.getUniqueId();
        int totalSec = plugin.getConfigManager().getSessionTimeout();
        final int[] left = {totalSec};

        BukkitTask task = new BukkitRunnable() {
            @Override
            public void run() {
                if (!player.isOnline() || plugin.getSessionManager().isAuthenticated(uuid)) {
                    LoginCountdown.this.stop(uuid);
                    return;
                }
                if (left[0] <= 0) {
                    LoginCountdown.this.stop(uuid);
                    return;
                }
                String msg = plugin.getConfigManager().getRawMessage("login-countdown");
                if (msg == null || msg.isEmpty()) {
                    msg = "&ePlease log in within &c{seconds}&e seconds...";
                }
                msg = msg.replace("{seconds}", String.valueOf(left[0]));
                TitleUtil.actionBar(player, msg);
                left[0]--;
            }
        }.runTaskTimer(plugin, 20L, 20L);
        tasks.put(uuid, task);
    }

    public void stop(UUID uuid) {
        BukkitTask t = tasks.remove(uuid);
        if (t != null) t.cancel();
    }

    /** Alias of {@link #stop(UUID)} for callers that still use cancel. */
    public void cancel(UUID uuid) {
        stop(uuid);
    }

    public void shutdown() {
        for (BukkitTask t : tasks.values()) {
            t.cancel();
        }
        tasks.clear();
    }
}
