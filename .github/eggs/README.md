# Pterodactyl eggs — SecureAuth

| File | Dùng cho |
|------|----------|
| `egg-paper-secureauth.json` | Server Paper 1.21.x + plugin SecureAuth |
| `egg-velocity-secureauth.json` | Proxy Velocity + SecureAuthVelocity |
| `egg-discord-bot-secureauth.json` | Bot Discord 2FA (Node) |

## Import
Admin → Nests → Import Egg → chọn file JSON.

## Minecraft version
- Plugin `api-version: 1.21` → **Paper 1.21.x** khuyến nghị
- Vẫn có thể chạy trên Paper 1.20.x (Spigot API tương thích xuôi trong nhiều case; test trước)

## Sau khi tạo server Paper
1. Upload `SecureAuth-1.0.2.jar` → `/plugins`
2. (Tuỳ chọn) ProtocolLib
3. Sửa `plugins/SecureAuth/config.yml` (`api-secret`, Discord)
