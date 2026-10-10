package dev.tienday.secureauth.util;

import dev.tienday.secureauth.SecureAuthPlugin;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.entity.Player;

/**
 * Titles / action bars — text from lang/{locale}.yml via ConfigManager.
 */
public final class TitleUtil {

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();

    private TitleUtil() {}

    private static String msg(String key, String fallback) {
        SecureAuthPlugin pl = SecureAuthPlugin.getInstance();
        if (pl != null && pl.getConfigManager() != null) {
            String raw = pl.getConfigManager().getRawMessage(key);
            if (raw != null && !raw.isEmpty()) return raw;
        }
        return fallback;
    }

    public static void send(Player player, String title, String subtitle, int fadeIn, int stay, int fadeOut) {
        if (player == null) return;
        player.showTitle(net.kyori.adventure.title.Title.title(
                LEGACY.deserialize(title == null ? "" : title),
                LEGACY.deserialize(subtitle == null ? "" : subtitle),
                net.kyori.adventure.title.Title.Times.times(
                        java.time.Duration.ofMillis(fadeIn * 50L),
                        java.time.Duration.ofMillis(stay * 50L),
                        java.time.Duration.ofMillis(fadeOut * 50L)
                )
        ));
    }

    public static void actionBar(Player player, String message) {
        if (player == null) return;
        player.sendActionBar(LEGACY.deserialize(message == null ? "" : message));
    }

    public static void promptLogin(Player player, boolean registered) {
        if (registered) {
            send(player, msg("title-login", "&c&lLOGIN"),
                    msg("subtitle-login", "&7Use &f/login <password>"), 10, 60, 10);
            actionBar(player, msg("actionbar-login", "&e/login <password>"));
        } else {
            send(player, msg("title-register", "&e&lREGISTER"),
                    msg("subtitle-register", "&7Use &f/register <pass> <pass>"), 10, 60, 10);
            actionBar(player, msg("actionbar-register", "&e/register <password> <confirm>"));
        }
    }

    public static void loginSuccess(Player player) {
        send(player, msg("title-success", "&a&lSUCCESS"),
                msg("subtitle-success", "&7Welcome back!"), 5, 40, 10);
        actionBar(player, msg("actionbar-success", "&aLogin successful"));
    }

    public static void registerSuccess(Player player) {
        send(player, msg("title-registered", "&a&lREGISTERED"),
                msg("subtitle-registered", "&7Now use &f/login"), 5, 40, 10);
        actionBar(player, msg("actionbar-registered", "&aRegistered — use /login"));
    }

    public static void twoFaPrompt(Player player) {
        send(player, msg("title-2fa", "&b&l2FA"),
                msg("subtitle-2fa", "&7Enter the code from Discord"), 5, 50, 10);
        actionBar(player, msg("actionbar-2fa", "&e/login <2FA code>"));
    }

    /** New IP — wait for Approve / Deny on Discord */
    public static void newIpPrompt(Player player) {
        send(player, msg("title-new-ip", "&6&lNEW IP"),
                msg("subtitle-new-ip", "&7Open Discord → Approve or Deny"), 5, 80, 10);
        actionBar(player, msg("actionbar-new-ip", "&eCheck bot DM — Approve / Deny buttons"));
    }

    public static void premiumAuto(Player player) {
        send(player, msg("title-premium", "&a&lPREMIUM"),
                msg("subtitle-premium", "&7Auto login"), 5, 30, 10);
        actionBar(player, msg("actionbar-premium", "&aPremium auto-login"));
    }

    public static void loginDenied(Player player) {
        send(player, msg("title-denied", "&c&lDENIED"),
                msg("subtitle-denied", "&7Login denied on Discord"), 5, 40, 10);
        actionBar(player, msg("actionbar-denied", "&cLogin from this IP was denied"));
    }

    /** Alias used by LoginCommand */
    public static void ipConfirmPrompt(Player player) {
        newIpPrompt(player);
    }

    /** Alias used by LoginCommand */
    public static void premiumAutoLogin(Player player) {
        premiumAuto(player);
    }
}
