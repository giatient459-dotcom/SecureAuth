package dev.tienday.secureauth.util;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import net.kyori.adventure.title.Title;
import org.bukkit.Sound;
import org.bukkit.entity.Player;

import java.time.Duration;

/**
 * nLogin-style Title + ActionBar helpers.
 */
public final class TitleUtil {

    private static final LegacyComponentSerializer LEGACY =
            LegacyComponentSerializer.legacyAmpersand();

    private TitleUtil() {}

    public static void send(Player player, String title, String subtitle, int fadeIn, int stay, int fadeOut) {
        Title.Times times = Title.Times.times(
                Duration.ofMillis(fadeIn * 50L),
                Duration.ofMillis(stay * 50L),
                Duration.ofMillis(fadeOut * 50L)
        );
        player.showTitle(Title.title(
                LEGACY.deserialize(title == null ? "" : title),
                LEGACY.deserialize(subtitle == null ? "" : subtitle),
                times
        ));
    }

    public static void actionBar(Player player, String message) {
        player.sendActionBar(LEGACY.deserialize(message == null ? "" : message));
    }

    public static void loginPrompt(Player player, boolean registered) {
        if (registered) {
            send(player, "&c&lĐĂNG NHẬP", "&7Dùng &f/login <mật khẩu>", 10, 60, 10);
            actionBar(player, "&e/login <password> &7hoặc code Discord 2FA");
        } else {
            send(player, "&e&lREGISTER", "&7Use &f/register <pass> <pass>", 10, 60, 10);
            actionBar(player, "&e/register <password> <confirm>");
        }
    }

    public static void loginSuccess(Player player) {
        send(player, "&a&lSUCCESS", "&7Welcome back!", 5, 40, 10);
        actionBar(player, "&aLogin successful");
        try {
            player.playSound(player.getLocation(), Sound.ENTITY_PLAYER_LEVELUP, 1f, 1.2f);
        } catch (Exception ignored) {}
    }

    public static void registerSuccess(Player player) {
        send(player, "&a&lREGISTERED", "&7Now use &f/login", 5, 40, 10);
        actionBar(player, "&aRegistered — use /login");
        try {
            player.playSound(player.getLocation(), Sound.ENTITY_PLAYER_LEVELUP, 1f, 1.0f);
        } catch (Exception ignored) {}
    }

    public static void twoFaPrompt(Player player) {
        send(player, "&b&l2FA", "&7Enter the code from Discord", 5, 50, 10);
        actionBar(player, "&e/login <2FA code>");
    }

    /** New IP — wait for Approve / Deny on Discord */
    public static void ipConfirmPrompt(Player player) {
        send(player, "&6&lNEW IP", "&7Open Discord → Approve or Deny", 5, 80, 10);
        actionBar(player, "&eCheck bot DM — Approve / Deny buttons");
    }

    public static void premiumAutoLogin(Player player) {
        send(player, "&a&lPREMIUM", "&7Auto login", 5, 30, 10);
        actionBar(player, "&aPremium auto-login");
        try {
            player.playSound(player.getLocation(), Sound.ENTITY_PLAYER_LEVELUP, 1f, 1.4f);
        } catch (Exception ignored) {}
    }

    public static void loginDenied(Player player) {
        send(player, "&c&lDENIED", "&7Login denied on Discord", 5, 40, 10);
        actionBar(player, "&cLogin from this IP was denied");
    }
}

