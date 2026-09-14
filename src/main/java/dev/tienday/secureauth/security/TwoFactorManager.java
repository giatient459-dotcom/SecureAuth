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

    /**
     * FIX: Thêm TOO_MANY_ATTEMPTS.
     * Khi player nhập sai code 2FA quá MAX_2FA_ATTEMPTS lần, code bị huỷ
     * và trả về giá trị này để LoginCommand kick player.
     */
    public enum VerifyResult { VALID, INVALID, EXPIRED, NOT_FOUND, TOO_MANY_ATTEMPTS }
    public enum SendResult   { SENT, COOLDOWN, FAILED }

    /** FIX: Số lần nhập sai tối đa trước khi huỷ code. */
    private static final int MAX_2FA_ATTEMPTS = 3;

    private static final String DIGITS = "0123456789";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SecureAuthPlugin plugin;
    private final Map<String, PendingCode> pendingCodes  = new ConcurrentHashMap<>();
    private final Map<String, Long>        lastSentAt    = new ConcurrentHashMap<>();
    /** FIX: Đếm số lần nhập sai của từng player trong phiên 2FA hiện tại. */
    private final Map<String, Integer>     verifyAttempts = new ConcurrentHashMap<>();

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
        // FIX: reset bộ đếm sai mỗi khi gửi code mới.
        verifyAttempts.remove(uuid);

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

    /**
     * FIX: Giới hạn số lần nhập sai.
     * - Nhập đúng  → reset counter, xoá code, trả VALID.
     * - Nhập sai lần 1..MAX-1 → tăng counter, trả INVALID (code vẫn còn).
     * - Nhập sai lần thứ MAX  → xoá code + counter, trả TOO_MANY_ATTEMPTS.
     * - Hết hạn → xoá code + counter, trả EXPIRED.
     */
    public VerifyResult verifyCode(String uuid, String input) {
        if (uuid == null || input == null) return VerifyResult.NOT_FOUND;
        PendingCode pending = pendingCodes.get(uuid);
        if (pending == null) return VerifyResult.NOT_FOUND;

        if (System.currentTimeMillis() > pending.expiresAt()) {
            pendingCodes.remove(uuid, pending);
            verifyAttempts.remove(uuid);
            return VerifyResult.EXPIRED;
        }

        String trimmed = input.trim();
        boolean match = constantTimeStringEquals(pending.code(), trimmed);
        if (match) {
            pendingCodes.remove(uuid, pending);
            verifyAttempts.remove(uuid);
            return VerifyResult.VALID;
        }

        int attempts = verifyAttempts.merge(uuid, 1, Integer::sum);
        if (attempts >= MAX_2FA_ATTEMPTS) {
            pendingCodes.remove(uuid, pending);
            verifyAttempts.remove(uuid);
            return VerifyResult.TOO_MANY_ATTEMPTS;
        }
        return VerifyResult.INVALID;
    }

    public boolean hasPendingCode(String uuid) {
        PendingCode p = pendingCodes.get(uuid);
        if (p == null) return false;
        if (System.currentTimeMillis() > p.expiresAt()) {
            pendingCodes.remove(uuid, p);
            verifyAttempts.remove(uuid);
            return false;
        }
        return true;
    }

    /** Số lần nhập sai còn lại của player (dùng để hiển thị cho player). */
    public int remainingAttempts(String uuid) {
        if (uuid == null) return MAX_2FA_ATTEMPTS;
        return Math.max(0, MAX_2FA_ATTEMPTS - verifyAttempts.getOrDefault(uuid, 0));
    }

    /** String-keyed variant. */
    public void clearCode(String uuid) {
        if (uuid != null) {
            pendingCodes.remove(uuid);
            lastSentAt.remove(uuid);
            // FIX: dọn counter khi huỷ phiên.
            verifyAttempts.remove(uuid);
        }
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

    // ---- HTTP to bot ----

    private boolean callBotSendDm(String discordId, String code, int expirySeconds) {
        String apiUrl    = plugin.getConfigManager().getBotApiUrl();
        String apiSecret = plugin.getConfigManager().getBotApiSecret();
        int    timeoutMs = plugin.getConfigManager().getBotApiTimeout();

        if (!discordId.matches("\\d{5,32}")) {
            plugin.getLogger().warning("Refusing 2FA DM: invalid discord_id format");
            return false;
        }
        if (!code.matches("\\d{4,10}")) {
            return false;
        }

        String body = "{\"discord_id\":\"" + discordId + "\","
                + "\"code\":\"" + code + "\","
                + "\"expiry_seconds\":" + expirySeconds + "}";

        HttpURLConnection conn = null;
        try {
            URL url = URI.create(apiUrl + "/send-2fa").toURL();
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
                    "Failed to reach Discord bot for 2FA DM (discord_id=" + redacted + "): "
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
