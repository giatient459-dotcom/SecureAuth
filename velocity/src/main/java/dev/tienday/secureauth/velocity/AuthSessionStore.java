package dev.tienday.secureauth.velocity;

import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * UUID → authenticated-at millis.
 * TTL optional (0 = until disconnect only).
 */
public final class AuthSessionStore {

    private final Map<UUID, Long> authenticated = new ConcurrentHashMap<>();
    private final long ttlMs;

    public AuthSessionStore(long ttlMs) {
        this.ttlMs = Math.max(0L, ttlMs);
    }

    public void markAuthenticated(UUID uuid) {
        if (uuid != null) {
            authenticated.put(uuid, System.currentTimeMillis());
        }
    }

    public void invalidate(UUID uuid) {
        if (uuid != null) {
            authenticated.remove(uuid);
        }
    }

    public boolean isAuthenticated(UUID uuid) {
        if (uuid == null) return false;
        Long at = authenticated.get(uuid);
        if (at == null) return false;
        if (ttlMs > 0 && System.currentTimeMillis() - at > ttlMs) {
            authenticated.remove(uuid, at);
            return false;
        }
        return true;
    }

    public void clearExpired() {
        if (ttlMs <= 0) return;
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<UUID, Long>> it = authenticated.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<UUID, Long> e = it.next();
            if (now - e.getValue() > ttlMs) {
                it.remove();
            }
        }
    }

    public int size() {
        return authenticated.size();
    }
}
