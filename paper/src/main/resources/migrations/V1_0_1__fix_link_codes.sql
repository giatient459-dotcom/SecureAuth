-- =========================================================================
-- SecureAuth Migration Script
-- Version: 1.0.1
-- Target: SQLite (plugins/SecureAuth/secureauth.db)
-- =========================================================================
-- Mục đích:
--   - Thêm cột register_ip + last_login_ip vào sa_players
--   - Tạo indexes cần thiết
--   - Fix lỗi "no such column: register_ip"
--
-- Chạy file này khi:
--   - Plugin báo lỗi "no such column: register_ip"
--   - Update từ version cũ lên 1.0.1+
--   - Database bị miss cột/index
--
-- Backup trước khi chạy:
--   cp secureauth.db secureauth.db.backup.$(date +%Y%m%d)
-- =========================================================================

-- -------------------------------------------------------------------------
-- BƯỚC 1: Thêm cột còn thiếu vào sa_players
-- -------------------------------------------------------------------------
-- Lưu ý: SQLite không có "ADD COLUMN IF NOT EXISTS"
-- Nếu cột đã tồn tại → báo lỗi "duplicate column name" → bỏ qua bước này

ALTER TABLE sa_players ADD COLUMN register_ip TEXT;
ALTER TABLE sa_players ADD COLUMN last_login_ip TEXT;

-- -------------------------------------------------------------------------
-- BƯỚC 2: Tạo indexes (sau khi cột đã tồn tại)
-- -------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_sa_players_username
    ON sa_players(username);

CREATE INDEX IF NOT EXISTS idx_sa_players_register_ip
    ON sa_players(register_ip);

CREATE INDEX IF NOT EXISTS idx_sa_players_discord
    ON sa_players(discord_id);

-- -------------------------------------------------------------------------
-- BƯỚC 3: Unique partial index cho discord_id
-- (chỉ unique khi discord_id không NULL)
-- -------------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS uk_sa_players_discord
    ON sa_players(discord_id)
    WHERE discord_id IS NOT NULL;

-- -------------------------------------------------------------------------
-- BƯỚC 4: Index cho bảng security log
-- -------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_sa_security_log_uuid_time
    ON sa_security_log(uuid, time);

-- =========================================================================
-- KIỂM TRA SAU KHI CHẠY:
-- =========================================================================
-- sqlite3 secureauth.db "PRAGMA table_info(sa_players);"
-- sqlite3 secureauth.db ".indexes sa_players"
-- sqlite3 secureauth.db ".tables"
--
-- Nếu vẫn lỗi "no such table: sa_players" → database chưa có bảng gốc
-- → Xóa database và restart server để plugin tạo mới.
-- =========================================================================
