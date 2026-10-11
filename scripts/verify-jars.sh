#!/usr/bin/env bash
# SecureAuth — verify Paper + Velocity + BungeeCord JARs
set -euo pipefail

VERSION="${PROJECT_VERSION:-1.0.3}"
PAPER_JAR="${PAPER_JAR:-paper/target/SecureAuth-${VERSION}.jar}"
VEL_JAR="${VEL_JAR:-velocity/target/SecureAuthVelocity-${VERSION}.jar}"
BUNGEE_JAR="${BUNGEE_JAR:-bungee/target/SecureAuthBungee-${VERSION}.jar}"

echo "== Locate JARs =="
ls -la paper/target/*.jar 2>/dev/null || true
ls -la velocity/target/*.jar 2>/dev/null || true
ls -la bungee/target/*.jar 2>/dev/null || true

test -f "$PAPER_JAR"  || { echo "::error::Missing $PAPER_JAR"; exit 1; }
test -f "$VEL_JAR"    || { echo "::error::Missing $VEL_JAR"; exit 1; }
test -f "$BUNGEE_JAR" || { echo "::error::Missing $BUNGEE_JAR"; exit 1; }

echo "Paper:    $(stat -c%s "$PAPER_JAR") bytes"
echo "Velocity: $(stat -c%s "$VEL_JAR") bytes"
echo "Bungee:   $(stat -c%s "$BUNGEE_JAR") bytes"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# ===== PAPER =====
echo ""; echo "== Paper JAR =="
for path in 'plugin.yml' 'dev/tienday/secureauth/SecureAuthPlugin.class' 'org/sqlite/JDBC.class'; do
  jar tf "$PAPER_JAR" | grep -qF "$path" \
    || { echo "::error::Missing in Paper JAR: $path"; exit 1; }
done
unzip -p "$PAPER_JAR" plugin.yml > "$TMP/plugin.yml"
grep -qE 'main:[[:space:]]*dev\.tienday\.secureauth\.SecureAuthPlugin' "$TMP/plugin.yml" \
  || { echo "::error::plugin.yml main incorrect"; exit 1; }

# ===== VELOCITY =====
echo ""; echo "== Velocity JAR =="
jar tf "$VEL_JAR" | grep -qE 'velocity-plugin\.json$' \
  || { echo "::error::velocity-plugin.json missing"; exit 1; }
jar tf "$VEL_JAR" | grep -qE 'SecureAuthVelocity\.class$' \
  || { echo "::error::SecureAuthVelocity.class missing"; exit 1; }

# ===== BUNGEECORD =====
echo ""; echo "== BungeeCord JAR =="
jar tf "$BUNGEE_JAR" | grep -qE 'bungee\.yml$' \
  || { echo "::error::bungee.yml missing"; exit 1; }
jar tf "$BUNGEE_JAR" | grep -qE 'SecureAuthBungee\.class$' \
  || { echo "::error::SecureAuthBungee.class missing"; exit 1; }

echo ""; echo "== RESULT OK =="
