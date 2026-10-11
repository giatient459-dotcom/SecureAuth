package dev.tienday.secureauth.bungee;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class AuthSessionStore {

    private final Map<UUID, Long> authenticated = new ConcurrentHashMap<>();
    private final long timeoutMs;

    public AuthSessionStore(long timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    public void markAuthenticated(UUID uuid) {
        authenticated.put(uuid, System.currentTimeMillis());
    }

    public boolean isAuthenticated(UUID uuid) {
        Long t = authenticated.get(uuid);
        if (t == null) return false;
        if (timeoutMs > 0 && System.currentTimeMillis() - t > timeoutMs) {
            authenticated.remove(uuid);
            return false;
        }
        return true;
    }

    public void clear(UUID uuid) {
        authenticated.remove(uuid);
    }

    public void clearExpired() {
        if (timeoutMs <= 0) return;
        long now = System.currentTimeMillis();
        authenticated.entrySet().removeIf(e -> now - e.getValue() > timeoutMs);
    }
}
