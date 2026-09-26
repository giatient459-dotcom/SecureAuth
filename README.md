# SecureAuth (monorepo)

| Module | Artifact | Runtime |
|--------|----------|---------|
| `paper/` | `SecureAuth-1.0.2.jar` | Paper/Purpur 1.21.x · Java 21 |
| `velocity/` | `SecureAuthVelocity-1.0.2.jar` | Velocity 3.x · Java 17+ |

## Build all
```bash
mvn -B package
```

## Build one module
```bash
mvn -B package -pl paper -am
mvn -B package -pl velocity -am
```

## Layout
```
SecureAuth/
├── pom.xml          # parent
├── paper/           # ← put existing Paper sources here
│   ├── pom.xml
│   └── src/main/java/dev/tienday/secureauth/...
└── velocity/        # companion (included)
    ├── pom.xml
    └── src/main/java/dev/tienday/secureauth/velocity/...
```

## Migrate existing Paper repo
1. Move current `src/` + resources into `paper/`
2. Replace root `pom.xml` with parent
3. Keep Paper build config in `paper/pom.xml`
4. Add `velocity/` module (already scaffolded)

Paper `config.yml`:
```yaml
velocity:
  notify-url: "http://127.0.0.1:20335/auth/notify"
  backend-secret: "SAME_SECRET"
```
