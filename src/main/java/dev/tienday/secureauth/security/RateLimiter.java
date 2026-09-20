package dev.tienday.secureauth.security;

import dev.tienday.secureauth.SecureAuthPlugin;
import org.bukkit.scheduler.BukkitTask;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe rate limiter with two mechanisms:
 *  1. Failure counter + lockout (for /login).
 *  2. Sliding-window token bucket (for /register, /link).
 */
public class RateLimiter {

    private record AttemptRecord(int count, long lockedUntil) { }

    private static final class TokenBucket {
        long windowStart;
        int count;
    }

    private final SecureAuthPlugin plugin;
    private final Map<String, AttemptRecord> attempts = new ConcurrentHashMap<>();
    private final Map<String, TokenBucket> tokens = new ConcurrentHashMap<>();

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

    // ---- Failure counter (login) ----

    public boolean isLocked(String key) {
        if (key == null) return false;
        AttemptRecord r = attempts.get(key);
        if (r == null) return false;
        long now = System.currentTimeMillis();
        if (r.lockedUntil() > 0 && now < r.lockedUntil()) return true;
        if (r.lockedUntil() > 0) attempts.remove(key, r);
        return false;
    }

    public long secondsRemaining(String key) {
        if (key == null) return 0;
        AttemptRecord r = attempts.get(key);
        if (r == null || r.lockedUntil() <= 0) return 0;
        long remaining = (r.lockedUntil() - System.currentTimeMillis()) / 1000L;
        return Math.max(0, remaining);
    }

    public boolean recordFailure(String key) {
        if (key == null) return false;
        int maxAttempts = plugin.getConfigManager().getMaxLoginAttempts();
        int lockoutSec  = plugin.getConfigManager().getLockoutDuration();
        long now = System.currentTimeMillis();

        AttemptRecord updated = attempts.compute(key, (k, v) -> {
            int current = (v == null) ? 0 : v.count();
            if (v != null && v.lockedUntil() > 0 && now >= v.lockedUntil()) current = 0;
            int newCount = current + 1;
            if (newCount >= maxAttempts) {
                return new AttemptRecord(newCount, now + lockoutSec * 1000L);
            }
            return new AttemptRecord(newCount, 0);
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

    // ---- Token bucket (register / link) ----

    public boolean tryAcquireToken(String key, int maxPerWindow, long windowMs) {
        if (key == null || maxPerWindow <= 0 || windowMs <= 0) return true;
        long now = System.currentTimeMillis();

        TokenBucket bucket = tokens.compute(key, (k, b) -> {
            if (b == null || (now - b.windowStart) >= windowMs) {
                TokenBucket nb = new TokenBucket();
                nb.windowStart = now;
                nb.count = 1;
                return nb;
            }
            b.count++;
            return b;
        });
        return bucket.count <= maxPerWindow;
    }

    public void clearTokens(String key) {
        if (key != null) tokens.remove(key);
    }

    // ---- Cleanup ----

    private void cleanupExpired() {
        long now = System.currentTimeMillis();
        attempts.entrySet().removeIf(e -> {
            AttemptRecord r = e.getValue();
            return r.lockedUntil() > 0 && now >= r.lockedUntil();
        });
        tokens.entrySet().removeIf(e -> (now - e.getValue().windowStart) > 30 * 60_000L);
    }
}