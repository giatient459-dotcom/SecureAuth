package dev.tienday.secureauth.license;

/**
 * Nội dung license đã giải mã (trước khi verify HMAC).
 */
public final class LicensePayload {
    public final String hwid;
    public final long expiryEpochSec;
    public final String customer;
    public final String signature;

    public LicensePayload(String hwid, long expiryEpochSec, String customer, String signature) {
        this.hwid = hwid;
        this.expiryEpochSec = expiryEpochSec;
        this.customer = customer;
        this.signature = signature;
    }

    public boolean isExpired() {
        return System.currentTimeMillis() / 1000L > expiryEpochSec;
    }
}
