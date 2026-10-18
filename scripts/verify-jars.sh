#!/usr/bin/env bash
# SecureAuth — verify Paper + Velocity + BungeeCord Gradle JARs
set -euo pipefail

VERSION="${PROJECT_VERSION:-1.0.3}"
PAPER_JAR="${PAPER_JAR:-paper/build/libs/SecureAuth-${VERSION}.jar}"
VEL_JAR="${VEL_JAR:-velocity/build/libs/SecureAuthVelocity-${VERSION}.jar}"
BUNGEE_JAR="${BUNGEE_JAR:-bungee/build/libs/SecureAuthBungee-${VERSION}.jar}"

echo "== Locate JARs =="
ls -la paper/build/libs/*.jar 2>/dev/null || true
ls -la velocity/build/libs/*.jar 2>/dev/null || true
ls -la bungee/build/libs/*.jar 2>/dev/null || true

test -f "$PAPER_JAR"  || { echo "::error::Missing $PAPER_JAR"; exit 1; }
test -f "$VEL_JAR"    || { echo "::error::Missing $VEL_JAR"; exit 1; }
test -f "$BUNGEE_JAR" || { echo "::error::Missing $BUNGEE_JAR"; exit 1; }

echo "Paper:    $(stat -c%s "$PAPER_JAR") bytes"
echo "Velocity: $(stat -c%s "$VEL_JAR") bytes"
echo "Bungee:   $(stat -c%s "$BUNGEE_JAR") bytes"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

echo ""; echo "== Paper JAR =="
for path in 'plugin.yml' 'dev/tienday/secureauth/SecureAuthPlugin.class' 'org/sqlite/JDBC.class'; do
  jar tf "$PAPER_JAR" | grep -qF "$path" \
    || { echo "::error::Missing in Paper JAR: $path"; exit 1; }
done
unzip -p "$PAPER_JAR" plugin.yml > "$TMP/plugin.yml"
grep -qE 'main:[[:space:]]*dev\.tienday\.secureauth\.SecureAuthPlugin' "$TMP/plugin.yml" \
  || { echo "::error::plugin.yml main incorrect"; exit 1; }
grep -qE "version:[[:space:]]*['\"]?${VERSION}" "$TMP/plugin.yml" \
  || { echo "::error::plugin.yml version mismatch"; exit 1; }

echo ""; echo "== Velocity JAR =="
jar tf "$VEL_JAR" | grep -qE 'velocity-plugin\.json$' \
  || { echo "::error::velocity-plugin.json missing"; exit 1; }
jar tf "$VEL_JAR" | grep -qE 'SecureAuthVelocity\.class$' \
  || { echo "::error::SecureAuthVelocity.class missing"; exit 1; }
unzip -p "$VEL_JAR" velocity-plugin.json | grep -q "\"version\"[[:space:]]*:[[:space:]]*\"$VERSION\"" \
  || { echo "::error::Velocity version mismatch"; exit 1; }

echo ""; echo "== BungeeCord JAR =="
jar tf "$BUNGEE_JAR" | grep -qE 'bungee\.yml$' \
  || { echo "::error::bungee.yml missing"; exit 1; }
jar tf "$BUNGEE_JAR" | grep -qE 'SecureAuthBungee\.class$' \
  || { echo "::error::SecureAuthBungee.class missing"; exit 1; }
unzip -p "$BUNGEE_JAR" bungee.yml | grep -qE "version:[[:space:]]*['\"]?${VERSION}" \
  || { echo "::error::Bungee version mismatch"; exit 1; }

echo ""; echo "== RESULT OK =="
