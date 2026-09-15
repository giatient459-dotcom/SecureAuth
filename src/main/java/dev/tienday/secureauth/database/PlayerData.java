package dev.tienday.secureauth.database;

public class PlayerData {

    private final String uuid;
    private final String username;
    private final String passwordHash;
    private final String discordId;
    private final boolean twoFaEnabled;
    private final long registeredAt;
    private final long lastLoginAt;
    private final boolean disabled;      // ← THÊM

    public PlayerData(String uuid, String username, String passwordHash,
                      String discordId, boolean twoFaEnabled,
                      long registeredAt, long lastLoginAt,
                      boolean disabled) {   // ← THÊM tham số thứ 8
        this.uuid = uuid;
        this.username = username;
        this.passwordHash = passwordHash;
        this.discordId = discordId;
        this.twoFaEnabled = twoFaEnabled;
        this.registeredAt = registeredAt;
        this.lastLoginAt = lastLoginAt;
        this.disabled = disabled;
    }

    public String getUuid()         { return uuid; }
    public String getUsername()     { return username; }
    public String getPasswordHash() { return passwordHash; }
    public String getDiscordId()    { return discordId; }
    public boolean isTwoFaEnabled() { return twoFaEnabled && discordId != null; }
    public long getRegisteredAt()   { return registeredAt; }
    public long getLastLoginAt()    { return lastLoginAt; }

    /** FIX: dùng bởi LoginCommand để chặn account bị admin reset. */
    public boolean isDisabled() {
        // Kết hợp cả cột DB và sentinel "!disabled" trong password hash,
        // để tương thích với dữ liệu cũ trước khi có cột disabled.
        if (disabled) return true;
        return passwordHash == null || passwordHash.equals("!disabled");
    }
}
