package dev.tienday.secureauth.license;

/**
 * Parse + verify license key.
 * Format key (URL-safe Base64):  BASE64( hwid | expiryEpoch | customer | hmac )
 * Payload ký: hwid|expiry|customer  với HMAC-SHA256(secret)
 */
public final class LicenseValidator {

    public enum FailReason {
        EMPTY,
        MALFORMED,
        BAD_SIGNATURE,
        HWID_MISMATCH,
        EXPIRED,
        OK
    }

    public static final class Result {
        public final FailReason reason;
        public final LicensePayload payload;
        public final String message;

        public Result(FailReason reason, LicensePayload payload, String message) {
            this.reason = reason;
            this.payload = payload;
            this.message = message;
        }

        public boolean ok() {
            return reason == FailReason.OK;
        }
    }

    private LicenseValidator() {}

    public static Result validate(String keyText, String currentHwid) {
        if (keyText == null || keyText.isBlank()) {
            return new Result(FailReason.EMPTY, null, "License key empty");
        }
        String trimmed = keyText.trim().replaceAll("\\s+", "");
        try {
            String decoded = CryptoUtils.b64DecodeToString(trimmed);
            String[] parts = decoded.split("\\|", -1);
            if (parts.length != 4) {
                return new Result(FailReason.MALFORMED, null, "License format invalid (need 4 fields)");
            }
            String hwid = parts[0].trim().toLowerCase();
            long expiry = Long.parseLong(parts[1].trim());
            String customer = parts[2].trim();
            String sig = parts[3].trim();

            String toSign = hwid + "|" + expiry + "|" + customer;
            String expected = CryptoUtils.hmacSha256Base64(toSign, ObfStrings.hmacSecret());
            if (!CryptoUtils.constantTimeEquals(expected, sig)) {
                return new Result(FailReason.BAD_SIGNATURE, null, "License signature invalid");
            }

            LicensePayload payload = new LicensePayload(hwid, expiry, customer, sig);
            if (currentHwid == null || !hwid.equalsIgnoreCase(currentHwid.trim())) {
                return new Result(FailReason.HWID_MISMATCH, payload,
                        "HWID mismatch (key for " + hwid + ", this machine " + currentHwid + ")");
            }
            if (payload.isExpired()) {
                return new Result(FailReason.EXPIRED, payload, "License expired");
            }
            return new Result(FailReason.OK, payload, "OK");
        } catch (IllegalArgumentException e) {
            return new Result(FailReason.MALFORMED, null, "License Base64/parse error: " + e.getMessage());
        } catch (Exception e) {
            return new Result(FailReason.MALFORMED, null, "License error: " + e.getMessage());
        }
    }

    /** Sinh chuỗi ký + encode (dùng bởi KeyGen). */
    public static String issueKey(String hwid, long expiryEpochSec, String customer) {
        String h = hwid.trim().toLowerCase();
        String c = customer == null ? "customer" : customer.trim().replace("|", "_");
        String toSign = h + "|" + expiryEpochSec + "|" + c;
        String sig = CryptoUtils.hmacSha256Base64(toSign, ObfStrings.hmacSecret());
        String raw = h + "|" + expiryEpochSec + "|" + c + "|" + sig;
        return CryptoUtils.b64Encode(raw);
    }
}
