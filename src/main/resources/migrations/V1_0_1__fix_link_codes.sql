-- =========================================================================
-- SecureAuth migration v1.0.0 -> v1.0.1
-- =========================================================================

START TRANSACTION;

DROP TABLE IF EXISTS sa_link_codes;

CREATE TABLE sa_link_codes (
                               code       VARCHAR(16) NOT NULL PRIMARY KEY,
                               discord_id VARCHAR(32) NOT NULL,
                               expires_at BIGINT      NOT NULL,
                               INDEX idx_link_codes_expires (expires_at),
                               INDEX idx_link_codes_discord (discord_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

UPDATE sa_players p
    JOIN (
    SELECT uuid FROM sa_players
    WHERE discord_id IS NOT NULL
    GROUP BY discord_id
    HAVING COUNT(*) > 1
    ) d ON p.uuid = d.uuid
    SET p.discord_id = NULL, p.two_fa_enabled = 0;

ALTER TABLE sa_players
    ADD UNIQUE KEY uk_players_discord (discord_id);

UPDATE sa_players
SET password_hash = '!disabled'
WHERE password_hash LIKE 'RESET_BY_ADMIN_%';

COMMIT;