# SecureAuth

**Login / register** plugin for Paper (AuthMe-style) with optional **Velocity** and **BungeeCord** companion modules.  
Supports Discord 2FA, IP sessions, ProtocolLib (soft-depend), bStats, and scheduled SQLite backups.

| Module | Artifact | Requirements |
|--------|----------|--------------|
| **Paper** (backend) | `SecureAuth-1.0.3.jar` | **Paper** / **Purpur** 1.21.x (recommended), **Spigot** 1.21+ (best-effort), Java **21** |
| **Velocity** (proxy) | `SecureAuthVelocity-1.0.3.jar` | Velocity **3.5.x**, Java 17+ |
| **BungeeCord** (proxy) | `SecureAuthBungee-1.0.3.jar` | BungeeCord / **Waterfall**, Java 17+ |

**API version:** `1.21` · Declared support window: **1.21.x – 26.x** (primarily tested on **1.21.4**)

---

## Features

- `/register`, `/login`, `/changepassword`, `/link` (Discord)
- Discord 2FA via HTTP API (bot ↔ plugin)
- Login lobby (`/authsetspawn`) for unauthenticated players
- IP session (skip 2FA for the same IP within X hours)
- Rate limiting / lockout + optional Discord webhook alerts
- ProtocolLib soft-depend (packet blocking; optional)
- Anonymous bStats (plugin id `34505`; toggle in config)
- Scheduled SQLite backups
- Admin: `/authadmin` (reset, list, search, logs, backup…)
- Premium auto-login (opt-in; offline-mode UUID heuristic)

---

## Quick install (Paper)

1. Build or download the JAR from **Actions → Artifacts** / Releases  
2. Put `SecureAuth-1.0.3.jar` in `plugins/`  
3. (Recommended) install **ProtocolLib**  
4. Start the server, then edit `plugins/SecureAuth/config.yml`  
5. Change **`discord-bot.api-secret`** (do not leave the default)  
6. Stand at your lobby location → `/authsetspawn` (`secureauth.admin`)

```yaml
discord-bot:
  api-url: "http://127.0.0.1:20333"      # bot URL (depends on your topology)
  api-secret: "CHANGE_TO_A_LONG_RANDOM_SECRET"
  plugin-http-port: 20334
  plugin-http-bind: "127.0.0.1"          # remote bot: "0.0.0.0" + firewall + strong secret
```

- Bot on the **same host** as Paper → keep `127.0.0.1`  
- Bot on **another host** → set `plugin-http-bind: "0.0.0.0"` and allow only the bot IP

---

## Build from source

```bash
# Entire monorepo
mvn -B package

# Paper only
mvn -B package -pl paper -am

# Velocity only
mvn -B package -pl velocity -am
mvn -B package -pl bungee -am
```

Outputs:

- `paper/target/SecureAuth-1.0.3.jar`
- `velocity/target/SecureAuthVelocity-1.0.3.jar`
- `bungee/target/SecureAuthBungee-1.0.3.jar`

CI: `.github/workflows/build.yml` + `scripts/verify-jars.sh` (JAR integrity + `api-version` check).

---

## Repository layout

```text
SecureAuth/
├── pom.xml                 # parent POM
├── paper/                  # Paper plugin
│   ├── pom.xml
│   └── src/main/...
├── velocity/               # proxy companion
├── scripts/verify-jars.sh
└── .github/workflows/
```

---

## Player commands

| Command | Description |
|---------|-------------|
| `/register <pass> <pass>` | Create an account |
| `/login <pass> [2fa]` | Log in |
| `/link <code>` | Link Discord account |
| `/changepassword <old> <new> <new>` | Change password |
| `/uuid` | Show your UUID |

## Admin commands

| Command | Permission |
|---------|------------|
| `/authsetspawn` | `secureauth.admin` |
| `/authadmin ...` | `secureauth.admin` |

Other permissions: `secureauth.bypass`, `secureauth.force2fa`, `secureauth.manage-op`, …

---

## Velocity (optional)

1. Install `SecureAuthVelocity-1.0.3.jar` on the proxy  
2. Paper `config.yml`:

```yaml
velocity:
  notify-url: "http://127.0.0.1:20335/auth/notify"
  backend-secret: "SAME_SECRET_AS_VELOCITY"
```

## BungeeCord / Waterfall (optional)

1. Install `SecureAuthBungee-1.0.3.jar` on the **proxy** (`plugins/`)  
2. Edit `plugins/SecureAuthBungee/config.properties` — set `backend-secret` and `auth-server`  
3. Paper `config.yml` (same keys as Velocity):

```yaml
velocity:
  notify-url: "http://127.0.0.1:20335/auth/notify"
  backend-secret: "SAME_SECRET_AS_BUNGEE"
```

Paper notifies the proxy after a successful login; until then players can only stay on `auth-server`.

## Platform support matrix

| Platform | Support |
|----------|---------|
| Paper 1.21.x | **Full** (primary) |
| Purpur 1.21.x | **Full** (Paper API) |
| Spigot 1.21+ | **Best-effort** (same JAR; test Adventure/commands) |
| Folia | **Not supported** (`folia-supported: false`) |
| Velocity 3.x | Companion module |
| BungeeCord / Waterfall | Companion module |
| Fabric / Forge / NeoForge | **Not supported** (different API) |

---

## Discord bot

- Plugin exposes a local HTTP API (`plugin-http-port`, default `20334`)
- Example endpoints: `/auth/verify-credentials`, `/auth/health`, `/auth/ip-confirm`
- Auth header: `Authorization: Bearer <api-secret>`
- **Do not** share the SQLite file with the bot — use the HTTP API only

---

## Database

- Default **SQLite** (`plugins/SecureAuth/secureauth.db`, WAL mode)
- Automatic migrations (`register_ip`, `last_login_ip`, schema version tracking)

---

## License

See `LICENSE` in the repository.  
The current `monorepo-fix` line does **not** include an online license lock.

---

## Support

- Open a GitHub **Issue**
- Include Paper version, startup log, and a redacted config snippet (never post `api-secret`)

---

## Recent audit notes

- ProtocolLib: no blind packet cancel (avoids blocking `/login`)
- Configurable `plugin-http-bind`
- SQLite `busy_timeout` set to 10s
- `/authsetspawn` persists via `saveConfig()` (single `config.yml`)
- `LoginCountdown`: `stop` / `cancel` alias
- bStats id is hardcoded; config only has `metrics.enabled`
