package dev.tienday.secureauth.security;

import dev.tienday.secureauth.SecureAuthPlugin;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

public class TwoFactorManager {

    private record PendingCode(String code, long expiresAt) { }
    private record PendingIpConfirm(String ip, String token, long expiresAt) { }

    public enum VerifyResult { VALID, INVALID, EXPIRED, NOT_FOUND }
    public enum SendResult   { SENT, COOLDOWN, FAILED }
    public enum IpConfirmResult { APPROVED, DENIED, EXPIRED, NOT_FOUND }

    private static final String DIGITS = "0123456789";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SecureAuthPlugin plugin;
    private final Map<String, PendingCode> pendingCodes = new ConcurrentHashMap<>();
    private final Map<String, Long> lastSentAt = new ConcurrentHashMap<>();
    /** uuid -> pending IP confirm (Discord buttons) */
    private final Map<String, PendingIpConfirm> pendingIpConfirms = new ConcurrentHashMap<>();
    /** token -> uuid (bot callback) */
    private final Map<String, String> ipConfirmTokens = new ConcurrentHashMap<>();

    public TwoFactorManager(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    /**
     * Generates a 2FA code, stores it, and asks the bot to DM the player.
     * BLOCKING — must run off the main thread.
     */
    public SendResult generateAndSend(String uuid, String discordId) {
        if (uuid == null || discordId == null) return SendResult.FAILED;

        int cooldownSec = plugin.getConfigManager().getTwoFaMinResendInterval();
        long now = System.currentTimeMillis();
        Long last = lastSentAt.get(uuid);
        if (cooldownSec > 0 && last != null && (now - last) < cooldownSec * 1000L) {
            return SendResult.COOLDOWN;
        }

        int length = plugin.getConfigManager().getTwoFaCodeLength();
        int expirySec = plugin.getConfigManager().getTwoFaCodeExpiry();

        String code = generateCode(length);
        long expiresAt = now + expirySec * 1000L;
        PendingCode pending = new PendingCode(code, expiresAt);

        pendingCodes.put(uuid, pending);
        lastSentAt.put(uuid, now);

        boolean sent = callBotSendDm(discordId, code, expirySec);
        if (!sent) {
            pendingCodes.remove(uuid, pending);
            lastSentAt.remove(uuid);
            return SendResult.FAILED;
        }
        return SendResult.SENT;
    }

    public long getResendCooldownSeconds(String uuid) {
        int cooldownSec = plugin.getConfigManager().getTwoFaMinResendInterval();
        if (cooldownSec <= 0) return 0;
        Long last = lastSentAt.get(uuid);
        if (last == null) return 0;
        long elapsed = (System.currentTimeMillis() - last) / 1000L;
        return Math.max(0, cooldownSec - elapsed);
    }

    public VerifyResult verifyCode(String uuid, String input) {
        if (uuid == null || input == null) return VerifyResult.NOT_FOUND;
        PendingCode pending = pendingCodes.get(uuid);
        if (pending == null) return VerifyResult.NOT_FOUND;

        if (System.currentTimeMillis() > pending.expiresAt()) {
            pendingCodes.remove(uuid, pending);
            return VerifyResult.EXPIRED;
        }

        String trimmed = input.trim();
        boolean match = constantTimeStringEquals(pending.code(), trimmed);
        if (match) {
            pendingCodes.remove(uuid, pending);
            return VerifyResult.VALID;
        }
        return VerifyResult.INVALID;
    }

    public boolean hasPendingCode(String uuid) {
        PendingCode p = pendingCodes.get(uuid);
        if (p == null) return false;
        if (System.currentTimeMillis() > p.expiresAt()) {
            pendingCodes.remove(uuid, p);
            return false;
        }
        return true;
    }

    /** UUID overload — convenience for callers that hold a UUID. */
    public void clearCode(UUID uuid) {
        if (uuid != null) clearCode(uuid.toString());
    }

    public boolean hasPendingCode(UUID uuid) {
        return uuid != null && hasPendingCode(uuid.toString());
    }

    public long getResendCooldownSeconds(UUID uuid) {
        return uuid == null ? 0 : getResendCooldownSeconds(uuid.toString());
    }

    // ---- IP confirm (Discord buttons) ----

    /**
     * Gửi DM Discord: IP mới đăng nhập — nút Xác nhận / Từ chối.
     * BLOCKING — chạy off main thread.
     */
    public SendResult sendIpConfirm(String uuid, String discordId, String playerName, String ip) {
        if (uuid == null || discordId == null || ip == null) return SendResult.FAILED;

        int cooldownSec = plugin.getConfigManager().getTwoFaMinResendInterval();
        long now = System.currentTimeMillis();
        Long last = lastSentAt.get(uuid);
        if (cooldownSec > 0 && last != null && (now - last) < cooldownSec * 1000L) {
            return SendResult.COOLDOWN;
        }

        int expirySec = plugin.getConfigManager().getIpConfirmExpirySeconds();
        String token = generateToken();
        PendingIpConfirm pending = new PendingIpConfirm(ip, token, now + expirySec * 1000L);
        pendingIpConfirms.put(uuid, pending);
        ipConfirmTokens.put(token, uuid);
        lastSentAt.put(uuid, now);

        boolean sent = callBotSendIpConfirm(discordId, playerName, ip, token, expirySec);
        if (!sent) {
            pendingIpConfirms.remove(uuid, pending);
            ipConfirmTokens.remove(token);
            lastSentAt.remove(uuid);
            return SendResult.FAILED;
        }
        return SendResult.SENT;
    }

    public boolean hasPendingIpConfirm(String uuid) {
        PendingIpConfirm p = pendingIpConfirms.get(uuid);
        if (p == null) return false;
        if (System.currentTimeMillis() > p.expiresAt()) {
            clearIpConfirm(uuid);
            return false;
        }
        return true;
    }

    public record IpConfirmResolve(IpConfirmResult result, String uuid) {}

    /**
     * Bot gọi khi user bấm nút. token + action=approve|deny
     */
    public IpConfirmResolve resolveIpConfirm(String token, String action) {
        if (token == null || action == null) {
            return new IpConfirmResolve(IpConfirmResult.NOT_FOUND, null);
        }
        String uuid = ipConfirmTokens.get(token);
        if (uuid == null) {
            return new IpConfirmResolve(IpConfirmResult.NOT_FOUND, null);
        }
        PendingIpConfirm p = pendingIpConfirms.get(uuid);
        if (p == null || !token.equals(p.token())) {
            ipConfirmTokens.remove(token);
            return new IpConfirmResolve(IpConfirmResult.NOT_FOUND, null);
        }
        if (System.currentTimeMillis() > p.expiresAt()) {
            clearIpConfirm(uuid);
            return new IpConfirmResolve(IpConfirmResult.EXPIRED, uuid);
        }
        clearIpConfirm(uuid);
        if ("approve".equalsIgnoreCase(action) || "confirm".equalsIgnoreCase(action)) {
            return new IpConfirmResolve(IpConfirmResult.APPROVED, uuid);
        }
        return new IpConfirmResolve(IpConfirmResult.DENIED, uuid);
    }

    public void clearIpConfirm(String uuid) {
        if (uuid == null) return;
        PendingIpConfirm p = pendingIpConfirms.remove(uuid);
        if (p != null) ipConfirmTokens.remove(p.token());
    }

    public void clearCode(String uuid) {
        if (uuid != null) {
            pendingCodes.remove(uuid);
            lastSentAt.remove(uuid);
            clearIpConfirm(uuid);
        }
    }

    // ---- HTTP to bot ----

    private boolean callBotSendDm(String discordId, String code, int expirySeconds) {
        String body = "{\"discord_id\":\"" + discordId + "\","
                + "\"code\":\"" + code + "\","
                + "\"expiry_seconds\":" + expirySeconds + "}";
        return postBot("/send-2fa", discordId, body);
    }

    private boolean callBotSendIpConfirm(String discordId, String playerName, String ip,
                                         String token, int expirySeconds) {
        String safeName = playerName == null ? "?" : playerName.replace("\"", "");
        String safeIp = ip.replace("\"", "");
        String body = "{\"discord_id\":\"" + discordId + "\","
                + "\"player\":\"" + safeName + "\","
                + "\"ip\":\"" + safeIp + "\","
                + "\"token\":\"" + token + "\","
                + "\"expiry_seconds\":" + expirySeconds + "}";
        return postBot("/send-ip-confirm", discordId, body);
    }

    private boolean postBot(String path, String discordId, String body) {
        String apiUrl    = plugin.getConfigManager().getBotApiUrl();
        String apiSecret = plugin.getConfigManager().getBotApiSecret();
        int    timeoutMs = plugin.getConfigManager().getBotApiTimeout();

        if (!discordId.matches("\\d{5,32}")) {
            plugin.getLogger().warning("Refusing bot DM: invalid discord_id format");
            return false;
        }

        HttpURLConnection conn = null;
        try {
            URL url = URI.create(apiUrl + path).toURL();
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + apiSecret);
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            int status = conn.getResponseCode();
            try (InputStream is = (status >= 200 && status < 300)
                    ? conn.getInputStream()
                    : conn.getErrorStream()) {
                if (is != null) {
                    byte[] buf = new byte[1024];
                    while (is.read(buf) != -1) { /* drain */ }
                }
            }
            return status == 200;
        } catch (IOException e) {
            String redacted = discordId.length() > 4
                    ? "****" + discordId.substring(discordId.length() - 4)
                    : "****";
            plugin.getLogger().log(Level.WARNING,
                    "Failed to reach Discord bot (" + path + ", discord_id=" + redacted + "): "
                            + e.getMessage());
            return false;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ---- helpers ----

    private String generateCode(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(DIGITS.charAt(SECURE_RANDOM.nextInt(DIGITS.length())));
        }
        return sb.toString();
    }

    private String generateToken() {
        byte[] buf = new byte[16];
        SECURE_RANDOM.nextBytes(buf);
        StringBuilder sb = new StringBuilder(32);
        for (byte b : buf) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private boolean constantTimeStringEquals(String a, String b) {
        if (a == null || b == null) return false;
        int maxLen = Math.max(a.length(), b.length());
        int diff = a.length() ^ b.length();
        for (int i = 0; i < maxLen; i++) {
            char ca = i < a.length() ? a.charAt(i) : 0;
            char cb = i < b.length() ? b.charAt(i) : 0;
            diff |= (ca ^ cb);
        }
        return diff == 0;
    }
}
