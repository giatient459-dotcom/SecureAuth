package dev.tienday.secureauth.database;

public class PlayerData {

    private final String uuid;
    private final String username;
    private final String passwordHash;
    private final String discordId;
    private final boolean twoFaEnabled;
    private final long registeredAt;
    private final long lastLoginAt;

    public PlayerData(String uuid, String username, String passwordHash,
                      String discordId, boolean twoFaEnabled,
                      long registeredAt, long lastLoginAt) {
        this.uuid = uuid;
        this.username = username;
        this.passwordHash = passwordHash;
        this.discordId = discordId;
        this.twoFaEnabled = twoFaEnabled;
        this.registeredAt = registeredAt;
        this.lastLoginAt = lastLoginAt;
    }

    public String getUuid()         { return uuid; }
    public String getUsername()     { return username; }
    public String getPasswordHash() { return passwordHash; }
    public String getDiscordId()    { return discordId; }
    public boolean isTwoFaEnabled() { return twoFaEnabled && discordId != null; }
    public long getRegisteredAt()   { return registeredAt; }
    public long getLastLoginAt()    { return lastLoginAt; }
}