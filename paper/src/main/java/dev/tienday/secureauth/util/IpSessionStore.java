package dev.tienday.secureauth.util;

import dev.tienday.secureauth.SecureAuthPlugin;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Remember successful login (uuid + IP) for X hours to skip 2FA.
 * In-memory only — resets on plugin reload (by design, safer).
 */
public final class IpSessionStore {

    private record Entry(String ip, long expiresAt) {}

    private final SecureAuthPlugin plugin;
    private final Map<String, Entry> trusted = new ConcurrentHashMap<>();

    public IpSessionStore(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public void remember(String uuid, String ip) {
        if (!plugin.getConfigManager().isIpSessionEnabled()) return;
        if (uuid == null || ip == null || ip.isBlank() || "unknown".equals(ip)) return;
        int hours = plugin.getConfigManager().getIpSessionHours();
        if (hours <= 0) return;
        long exp = System.currentTimeMillis() + hours * 3_600_000L;
        trusted.put(uuid, new Entry(ip, exp));
    }

    /** True if same UUID+IP still within window → skip 2FA (unless force2fa). */
    public boolean isTrusted(String uuid, String ip) {
        if (!plugin.getConfigManager().isIpSessionEnabled()) return false;
        if (uuid == null || ip == null) return false;
        Entry e = trusted.get(uuid);
        if (e == null) return false;
        long now = System.currentTimeMillis();
        if (now > e.expiresAt()) {
            trusted.remove(uuid, e);
            return false;
        }
        return e.ip().equals(ip);
    }

    public void clear(String uuid) {
        if (uuid != null) trusted.remove(uuid);
    }

    public void shutdown() {
        trusted.clear();
    }
}
