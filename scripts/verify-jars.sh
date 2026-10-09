#!/usr/bin/env bash
# SecureAuth — verify Paper + Velocity JARs
# Support window (user): 1.21.x - 26.x  →  api 1.21 … 1.26
set -euo pipefail

VERSION="${PROJECT_VERSION:-1.0.2}"
PAPER_JAR="${PAPER_JAR:-paper/target/SecureAuth-${VERSION}.jar}"
VEL_JAR="${VEL_JAR:-velocity/target/SecureAuthVelocity-${VERSION}.jar}"

MIN_MINOR=21
MAX_MINOR=26
WINDOW_LABEL="1.21.x - 26.x"
RECOMMENDED_MC="1.21.4"

echo "== Locate JARs =="
ls -la paper/target/*.jar 2>/dev/null || true
ls -la velocity/target/*.jar 2>/dev/null || true

test -f "$PAPER_JAR" || { echo "::error::Missing $PAPER_JAR"; exit 1; }
test -f "$VEL_JAR"   || { echo "::error::Missing $VEL_JAR"; exit 1; }

PAPER_SIZE=$(stat -c%s "$PAPER_JAR")
VEL_SIZE=$(stat -c%s "$VEL_JAR")
echo "Paper JAR size:   $PAPER_SIZE bytes"
echo "Velocity JAR size: $VEL_SIZE bytes"

if [ "$PAPER_SIZE" -lt 500000 ]; then
  echo "::error::Paper JAR too small ($PAPER_SIZE) — shade may have failed"
  exit 1
fi
if [ "$VEL_SIZE" -lt 2000 ]; then
  echo "::error::Velocity JAR too small ($VEL_SIZE)"
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "== Paper JAR contents =="
for path in \
  'plugin.yml' \
  'dev/tienday/secureauth/SecureAuthPlugin.class' \
  'dev/tienday/secureauth/database/DatabaseManager.class' \
  'dev/tienday/secureauth/util/LoginCountdown.class' \
  'org/sqlite/JDBC.class'
do
  jar tf "$PAPER_JAR" | grep -qF "$path" \
    || { echo "::error::Missing in Paper JAR: $path"; exit 1; }
done

jar tf "$PAPER_JAR" | grep -qE 'org/bouncycastle/' \
  || { echo "::error::bouncycastle not shaded"; exit 1; }

if jar tf "$PAPER_JAR" | grep -qiE 'bstats|Metrics'; then
  echo "bStats / Metrics present"
else
  echo "::warning::bstats path not found (check shade)"
fi

unzip -p "$PAPER_JAR" plugin.yml > "$TMP/plugin.yml"
echo "--- plugin.yml ---"
cat "$TMP/plugin.yml"

grep -qE 'main:[[:space:]]*dev\.tienday\.secureauth\.SecureAuthPlugin' "$TMP/plugin.yml" \
  || { echo "::error::plugin.yml main incorrect"; exit 1; }
grep -qE 'version:' "$TMP/plugin.yml" \
  || { echo "::error::plugin.yml missing version"; exit 1; }

API_VER=$(grep -E '^api-version:' "$TMP/plugin.yml" | head -1 | sed -E "s/^api-version:[[:space:]]*['\"]?([^'\"]+)['\"]?.*/\1/")
echo "api-version: $API_VER"

# 1.21 / 1.21.4 / 21 → minor number
MINOR=$(echo "$API_VER" | sed -E 's/^1\.([0-9]+).*/\1/; t; s/^([0-9]+).*/\1/')
if ! [[ "$MINOR" =~ ^[0-9]+$ ]]; then
  echo "::error::Cannot parse api-version '$API_VER'"
  exit 1
fi
if [ "$MINOR" -lt "$MIN_MINOR" ] || [ "$MINOR" -gt "$MAX_MINOR" ]; then
  echo "::error::api-version '$API_VER' outside window ${WINDOW_LABEL} (need 1.${MIN_MINOR}…1.${MAX_MINOR})"
  exit 1
fi

echo "Support window: ${WINDOW_LABEL}"
echo "Recommended:    $RECOMMENDED_MC"

if jar tf "$PAPER_JAR" | grep -qE '^config\.yml$'; then
  echo "config.yml present in JAR"
else
  echo "::warning::config.yml not at JAR root"
fi

echo "== Velocity JAR =="
jar tf "$VEL_JAR" | grep -qE 'velocity-plugin\.json$' \
  || { echo "::error::velocity-plugin.json missing"; exit 1; }
jar tf "$VEL_JAR" | grep -qE 'dev/tienday/secureauth/velocity/SecureAuthVelocity\.class$' \
  || { echo "::error::SecureAuthVelocity.class missing"; exit 1; }
jar tf "$VEL_JAR" | grep -qE 'dev/tienday/secureauth/velocity/AuthNotifyServer\.class$' \
  || { echo "::error::AuthNotifyServer.class missing"; exit 1; }

unzip -p "$VEL_JAR" velocity-plugin.json > "$TMP/velocity-plugin.json"
echo "--- velocity-plugin.json ---"
cat "$TMP/velocity-plugin.json"

grep -qE '"id"[[:space:]]*:[[:space:]]*"secureauth-velocity"' "$TMP/velocity-plugin.json" \
  || { echo "::error::velocity id incorrect"; exit 1; }
grep -qE '"main"[[:space:]]*:[[:space:]]*"dev\.tienday\.secureauth\.velocity\.SecureAuthVelocity"' "$TMP/velocity-plugin.json" \
  || { echo "::error::velocity main incorrect"; exit 1; }

echo "== RESULT OK =="
echo "PAPER=$PAPER_JAR ($PAPER_SIZE)"
echo "VELOCITY=$VEL_JAR ($VEL_SIZE)"
echo "MC_API=$API_VER WINDOW=${WINDOW_LABEL} RECOMMENDED=$RECOMMENDED_MC"
