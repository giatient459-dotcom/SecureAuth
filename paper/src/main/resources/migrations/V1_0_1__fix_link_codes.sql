-- =========================================================================
-- SecureAuth Migration v1.0.2
-- Target: SQLite (plugins/SecureAuth/secureauth.db)
-- Fix: no such column: register_ip
-- =========================================================================

-- Bước 1: Thêm cột còn thiếu
ALTER TABLE sa_players ADD COLUMN register_ip TEXT;
ALTER TABLE sa_players ADD COLUMN last_login_ip TEXT;

-- Bước 2: Tạo index cho register_ip
CREATE INDEX IF NOT EXISTS idx_sa_players_register_ip
    ON sa_players(register_ip);

-- Bước 3: Kiểm tra (optional)
-- PRAGMA table_info(sa_players);
-- .indexes sa_players
