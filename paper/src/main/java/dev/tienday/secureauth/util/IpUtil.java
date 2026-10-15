package dev.tienday.secureauth.util;

import org.bukkit.entity.Player;

import java.net.InetAddress;
import java.util.regex.Pattern;

/**
 * Safe player IP extraction — never returns "unknown" (that bypassed IP limits).
 * Returns null when IP cannot be determined or is invalid.
 */
public final class IpUtil {

    private static final Pattern IPV4 = Pattern.compile(
            "^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$");
    // simplified IPv6 (full + compressed forms)
    private static final Pattern IPV6 = Pattern.compile(
            "^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$");

    private IpUtil() {}

    /** @return host address or null */
    public static String safeIp(Player player) {
        if (player == null) return null;
        try {
            if (player.getAddress() == null || player.getAddress().getAddress() == null) {
                return null;
            }
            InetAddress addr = player.getAddress().getAddress();
            String ip = addr.getHostAddress();
            if (ip == null) return null;
            // strip IPv6 zone id (fe80::1%eth0)
            int pct = ip.indexOf('%');
            if (pct > 0) ip = ip.substring(0, pct);
            return isValidIp(ip) ? ip : null;
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean isValidIp(String ip) {
        if (ip == null || ip.isBlank()) return false;
        if ("unknown".equalsIgnoreCase(ip) || "0.0.0.0".equals(ip)) return false;
        return IPV4.matcher(ip).matches() || IPV6.matcher(ip).matches();
    }

    /** For DB/log — use empty string only when null IP must be stored. */
    public static String orEmpty(String ip) {
        return ip == null ? "" : ip;
    }
}
