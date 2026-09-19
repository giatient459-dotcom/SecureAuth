public Optional<PlayerData> getPlayerByUsername(String username) {
    final String sql = "SELECT * FROM sa_players WHERE LOWER(username) = LOWER(?) AND disabled = 0 LIMIT 1";
    try (PreparedStatement ps = getConn().prepareStatement(sql)) {
        ps.setString(1, username);
        try (ResultSet rs = ps.executeQuery()) {
            if (rs.next()) return Optional.of(mapRow(rs));
        }
    } catch (SQLException e) {
        plugin.getLogger().log(Level.SEVERE, "getPlayerByUsername error", e);
    }
    return Optional.empty();
}

public Optional<PlayerData> getPlayerByDiscordId(String discordId) {
    final String sql = "SELECT * FROM sa_players WHERE discord_id = ? AND disabled = 0 LIMIT 1";
    try (PreparedStatement ps = getConn().prepareStatement(sql)) {
        ps.setString(1, discordId);
        try (ResultSet rs = ps.executeQuery()) {
            if (rs.next()) return Optional.of(mapRow(rs));
        }
    } catch (SQLException e) {
        plugin.getLogger().log(Level.SEVERE, "getPlayerByDiscordId error", e);
    }
    return Optional.empty();
}

private PlayerData mapRow(ResultSet rs) throws SQLException {
    return new PlayerData(
            rs.getString("uuid"),
            rs.getString("username"),
            rs.getString("password_hash"),
            rs.getString("discord_id"),
            rs.getInt("two_fa_enabled") == 1,
            rs.getLong("registered_at"),
            rs.getLong("last_login_at")
    );
}
