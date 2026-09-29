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
            send(player, "&e&lĐĂNG KÝ", "&7Dùng &f/register <pass> <pass>", 10, 60, 10);
            actionBar(player, "&e/register <password> <confirm>");
        }
    }

    public static void loginSuccess(Player player) {
        send(player, "&a&lTHÀNH CÔNG", "&7Chào mừng trở lại!", 5, 40, 10);
        actionBar(player, "&aĐăng nhập thành công");
        try {
            player.playSound(player.getLocation(), Sound.ENTITY_PLAYER_LEVELUP, 1f, 1.2f);
        } catch (Exception ignored) {}
    }

    public static void registerSuccess(Player player) {
        send(player, "&a&lĐĂNG KÝ OK", "&7Giờ hãy &f/login", 5, 40, 10);
        actionBar(player, "&aĐăng ký thành công — dùng /login");
        try {
            player.playSound(player.getLocation(), Sound.ENTITY_PLAYER_LEVELUP, 1f, 1.0f);
        } catch (Exception ignored) {}
    }

    public static void twoFaPrompt(Player player) {
        send(player, "&b&l2FA", "&7Nhập mã từ Discord", 5, 50, 10);
        actionBar(player, "&e/login <mã 2FA>");
    }

    /** IP mới — chờ bấm Xác nhận / Từ chối trên Discord */
    public static void ipConfirmPrompt(Player player) {
        send(player, "&6&lIP MỚI", "&7Mở Discord → Xác nhận hoặc Từ chối", 5, 80, 10);
        actionBar(player, "&eKiểm tra DM Discord bot — nút Xác nhận / Từ chối");
    }

    public static void premiumAutoLogin(Player player) {
        send(player, "&a&lPREMIUM", "&7Tự đăng nhập", 5, 30, 10);
        actionBar(player, "&aPremium auto-login");
        try {
            player.playSound(player.getLocation(), Sound.ENTITY_PLAYER_LEVELUP, 1f, 1.4f);
        } catch (Exception ignored) {}
    }

    public static void loginDenied(Player player) {
        send(player, "&c&lTỪ CHỐI", "&7Đăng nhập bị từ chối trên Discord", 5, 40, 10);
        actionBar(player, "&cBạn đã từ chối đăng nhập từ IP này");
    }
}

