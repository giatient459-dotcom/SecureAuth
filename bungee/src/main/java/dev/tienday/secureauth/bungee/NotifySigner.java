package dev.tienday.secureauth.bungee;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * HMAC-SHA256 + timestamp + nonce for proxy /auth/notify.
 * Prevents replay of captured Bearer requests.
 */
public final class NotifySigner {

    /** Accept requests within ± this many ms of local clock. */
    public static final long MAX_SKEW_MS = 60_000L;
    private static final SecureRandom RNG = new SecureRandom();
    private static final Map<String, Long> USED_NONCES = new ConcurrentHashMap<>();

    private NotifySigner() {}

    public static String newNonce() {
        byte[] b = new byte[16];
        RNG.nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    public static String sign(String secret, String uuid, long ts, String nonce, String action) {
        String payload = uuid + "|" + ts + "|" + nonce + "|" + action;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC failed", e);
        }
    }

    /** Build JSON body for notify/invalidate. */
    public static String buildBody(String secret, String uuid, String action) {
        long ts = System.currentTimeMillis();
        String nonce = newNonce();
        String sig = sign(secret, uuid, ts, nonce, action);
        return "{\"uuid\":\"" + uuid + "\",\"ts\":" + ts
                + ",\"nonce\":\"" + nonce + "\",\"sig\":\"" + sig + "\"}";
    }

    /**
     * Validate ts/nonce/sig. Returns null if OK, else error reason.
     * action = "notify" | "invalidate"
     */
    public static String validate(String secret, String uuid, String tsStr, String nonce, String sig, String action) {
        if (secret == null || secret.isBlank()) return "secret";
        if (uuid == null || uuid.isBlank()) return "uuid";
        if (nonce == null || nonce.isBlank() || nonce.length() < 16) return "nonce";
        if (sig == null || sig.isBlank()) return "sig";
        long ts;
        try {
            ts = Long.parseLong(tsStr.trim());
        } catch (Exception e) {
            return "ts";
        }
        long now = System.currentTimeMillis();
        if (Math.abs(now - ts) > MAX_SKEW_MS) return "expired";
        // replay nonce
        pruneNonces(now);
        if (USED_NONCES.putIfAbsent(nonce, now + MAX_SKEW_MS * 2) != null) {
            return "replay";
        }
        String expected = sign(secret, uuid, ts, nonce, action);
        if (!constantTimeEq(expected, sig)) {
            USED_NONCES.remove(nonce);
            return "sig";
        }
        return null;
    }

    private static void pruneNonces(long now) {
        if (USED_NONCES.size() < 500) return;
        Iterator<Map.Entry<String, Long>> it = USED_NONCES.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Long> e = it.next();
            if (e.getValue() < now) it.remove();
        }
    }

    public static boolean constantTimeEq(String a, String b) {
        if (a == null || b == null) return false;
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        if (x.length != y.length) return false;
        int r = 0;
        for (int i = 0; i < x.length; i++) r |= x[i] ^ y[i];
        return r == 0;
    }
}
