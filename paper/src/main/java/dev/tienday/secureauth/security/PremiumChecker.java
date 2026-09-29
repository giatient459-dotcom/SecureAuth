package dev.tienday.secureauth.security;

import org.bukkit.entity.Player;

/**
 * Detect premium (online-mode / paid) accounts.
 * On offline-mode servers, Spigot still sets onlineMode=false for cracked;
 * premium players joining via authenticating proxy may still have valid UUID.
 */
public final class PremiumChecker {

    private PremiumChecker() {}

    /**
     * Best-effort: true if player appears to be a paid Minecraft account.
     * - Online-mode server: all players are premium.
     * - Offline-mode: check if UUID is offline-mode style (version 3) vs online (version 4).
     */
    public static boolean isPremium(Player player) {
        if (player == null) return false;
        if (player.getServer().getOnlineMode()) return true;
        // Online-mode UUIDs are version 4; offline-mode name-based are version 3
        return player.getUniqueId().version() == 4;
    }
}
