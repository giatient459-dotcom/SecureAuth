package dev.tienday.secureauth.database;

public class PlayerData {

    private final String uuid;
    private final String username;
    private final String passwordHash;
    private final String discordId;       // nullable
    private final boolean twoFaEnabled;
    private final long registeredAt;
    private final long lastLoginAt;
    private final boolean disabled;
    private final String lastLoginIp;     // nullable
    private final String registerIp;      // nullable

    public PlayerData(String uuid, String username, String passwordHash,
                      String discordId, boolean twoFaEnabled,
                      long registeredAt, long lastLoginAt,
                      boolean disabled, String lastLoginIp, String registerIp) {
        this.uuid = uuid != null ? uuid : "";
        this.username = username != null ? username : "";
        this.passwordHash = passwordHash != null ? passwordHash : "";
        this.discordId = discordId; // may be null
        this.twoFaEnabled = twoFaEnabled;
        this.registeredAt = registeredAt;
        this.lastLoginAt = lastLoginAt;
        this.disabled = disabled;
        this.lastLoginIp = lastLoginIp;
        this.registerIp = registerIp;
    }

    public String getUuid()         { return uuid; }
    public String getUsername()     { return username; }
    public String getPasswordHash() { return passwordHash; }
    public String getDiscordId()    { return discordId; }
    public boolean isTwoFaEnabled() {
        return twoFaEnabled && discordId != null && !discordId.isBlank();
    }
    public long getRegisteredAt()   { return registeredAt; }
    public long getLastLoginAt()    { return lastLoginAt; }
    public boolean isDisabled()     { return disabled; }
    public String getLastLoginIp()  { return lastLoginIp; }
    public String getRegisterIp()   { return registerIp; }
}
