package dev.tienday.secureauth.security;

import dev.tienday.secureauth.SecureAuthPlugin;
import org.bukkit.scheduler.BukkitTask;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe rate limiter:
 *  1. Failure counter + lockout (/login).
 *  2. Fixed-window token bucket (/register, /link, /changepassword).
 *
 * Quit: clearPlayerEphemeral(uuid) — does NOT clear login lockout.
 */
public class RateLimiter {

    private record AttemptRecord(int count, long lockedUntil, long lastUpdate) {}
    private record TokenWindow(long windowStart, int count) {}

    private final SecureAuthPlugin plugin;
    private final Map<String, AttemptRecord> attempts = new ConcurrentHashMap<>();
    private final Map<String, TokenWindow> tokens = new ConcurrentHashMap<>();
    private BukkitTask cleanupTask;

    public RateLimiter(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public void startCleanupTask() {
        cleanupTask = plugin.getServer().getScheduler().runTaskTimerAsynchronously(
                plugin, this::cleanupExpired, 20L * 300, 20L * 300);
    }

    public void shutdown() {
        if (cleanupTask != null) {
            cleanupTask.cancel();
            cleanupTask = null;
        }
        attempts.clear();
        tokens.clear();
    }

    public boolean isLocked(String key) {
        if (key == null) return false;
        AttemptRecord r = attempts.get(key);
        if (r == null) return false;
        long now = System.currentTimeMillis();
        if (r.lockedUntil() > 0 && now < r.lockedUntil()) return true;
        if (r.lockedUntil() > 0 && now >= r.lockedUntil()) {
            attempts.remove(key, r);
        }
        return false;
    }

    public long secondsRemaining(String key) {
        if (key == null) return 0;
        AttemptRecord r = attempts.get(key);
        if (r == null || r.lockedUntil() <= 0) return 0;
        return Math.max(0, (r.lockedUntil() - System.currentTimeMillis()) / 1000L);
    }

    /** @return true if this failure triggered lockout */
    public boolean recordFailure(String key) {
        if (key == null) return false;
        int maxAttempts = plugin.getConfigManager().getMaxLoginAttempts();
        int lockoutSec = plugin.getConfigManager().getLockoutDuration();
        long now = System.currentTimeMillis();

        AttemptRecord updated = attempts.compute(key, (k, v) -> {
            int current = 0;
            if (v != null) {
                if (v.lockedUntil() > 0 && now < v.lockedUntil()) return v;
                if (v.lockedUntil() > 0 && now >= v.lockedUntil()) current = 0;
                else current = v.count();
            }
            int newCount = current + 1;
            if (newCount >= maxAttempts) {
                return new AttemptRecord(newCount, now + lockoutSec * 1000L, now);
            }
            return new AttemptRecord(newCount, 0L, now);
        });
        return updated.lockedUntil() > now;
    }

    public void clearFailures(String key) {
        if (key != null) attempts.remove(key);
    }

    public int getFailureCount(String key) {
        if (key == null) return 0;
        AttemptRecord r = attempts.get(key);
        if (r == null) return 0;
        long now = System.currentTimeMillis();
        if (r.lockedUntil() > 0 && now >= r.lockedUntil()) return 0;
        return r.count();
    }

    public boolean tryAcquireToken(String key, int maxPerWindow, long windowMs) {
        if (key == null) return false;
        if (maxPerWindow <= 0 || windowMs <= 0) return true;
        long now = System.currentTimeMillis();
        final boolean[] allowed = {false};
        tokens.compute(key, (k, old) -> {
            if (old == null || (now - old.windowStart()) >= windowMs) {
                allowed[0] = true;
                return new TokenWindow(now, 1);
            }
            if (old.count() >= maxPerWindow) {
                allowed[0] = false;
                return old;
            }
            allowed[0] = true;
            return new TokenWindow(old.windowStart(), old.count() + 1);
        });
        return allowed[0];
    }

    public void clearTokens(String key) {
        if (key != null) tokens.remove(key);
    }

    /** Session quit: clear token buckets only — keep login lockout. */
    public void clearPlayerEphemeral(String uuid) {
        if (uuid == null || uuid.isBlank()) return;
        tokens.remove("register:" + uuid);
        tokens.remove("link:" + uuid);
        tokens.remove("cpw:" + uuid);
    }

    private void cleanupExpired() {
        long now = System.currentTimeMillis();
        long staleAttemptMs = 60 * 60_000L;
        long staleTokenMs = 30 * 60_000L;
        attempts.entrySet().removeIf(e -> {
            AttemptRecord r = e.getValue();
            if (r.lockedUntil() > 0) return now >= r.lockedUntil();
            return (now - r.lastUpdate()) >= staleAttemptMs;
        });
        tokens.entrySet().removeIf(e -> (now - e.getValue().windowStart()) >= staleTokenMs);
    }
}
