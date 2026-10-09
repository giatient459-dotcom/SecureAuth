#!/usr/bin/env bash
set -euo pipefail

VERSION="${PROJECT_VERSION:-1.0.2}"
PAPER_JAR="${PAPER_JAR:-paper/target/SecureAuth-${VERSION}.jar}"
VEL_JAR="${VEL_JAR:-velocity/target/SecureAuthVelocity-${VERSION}.jar}"
# Supported Minecraft (Paper) versions for this release
SUPPORTED_MC=("1.20" "1.20.1" "1.20.2" "1.20.4" "1.20.6" "1.21" "1.21.1" "1.21.3" "1.21.4")

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
jar tf "$PAPER_JAR" | grep -E '^plugin\.yml$' \
  || { echo "::error::plugin.yml missing"; exit 1; }
jar tf "$PAPER_JAR" | grep -E 'dev/tienday/secureauth/SecureAuthPlugin\.class$' \
  || { echo "::error::SecureAuthPlugin.class missing"; exit 1; }
jar tf "$PAPER_JAR" | grep -E 'dev/tienday/secureauth/database/DatabaseManager\.class$' \
  || { echo "::error::DatabaseManager.class missing"; exit 1; }
jar tf "$PAPER_JAR" | grep -E 'dev/tienday/secureauth/util/LoginCountdown\.class$' \
  || { echo "::error::LoginCountdown.class missing"; exit 1; }
jar tf "$PAPER_JAR" | grep -E 'org/sqlite/JDBC\.class$' \
  || { echo "::error::sqlite-jdbc not shaded"; exit 1; }
jar tf "$PAPER_JAR" | grep -E 'org/bouncycastle/' \
  || { echo "::error::bouncycastle not shaded"; exit 1; }
# bStats may be relocated
jar tf "$PAPER_JAR" | grep -E 'bstats|Metrics' \
  || echo "::warning::bstats/Metrics path not found (check shade relocate)"

unzip -p "$PAPER_JAR" plugin.yml > "$TMP/plugin.yml"
echo "--- plugin.yml ---"
cat "$TMP/plugin.yml"

grep -qE 'main:[[:space:]]*dev\.tienday\.secureauth\.SecureAuthPlugin' "$TMP/plugin.yml" \
  || { echo "::error::plugin.yml main incorrect"; exit 1; }
grep -qE 'version:' "$TMP/plugin.yml" \
  || { echo "::error::plugin.yml missing version"; exit 1; }

API_VER=$(grep -E '^api-version:' "$TMP/plugin.yml" | head -1 | sed "s/.*['\"]\\([^'\"]*\\)['\"].*/\\1/;s/.*:[[:space:]]*//")
echo "api-version declared: $API_VER"
# api-version is minimum; must be 1.20 or 1.21 family
if ! echo "$API_VER" | grep -qE '^1\.(20|21)'; then
  echo "::error::api-version '$API_VER' not in supported 1.20/1.21 family"
  exit 1
fi
echo "Supported MC targets (document): ${SUPPORTED_MC[*]}"
echo "Paper plugin targets MC >= $API_VER (Paper 1.20+ / 1.21.x recommended)"

# config.yml should be in jar
if jar tf "$PAPER_JAR" | grep -qE '^config\.yml$'; then
  echo "config.yml present in JAR"
else
  echo "::warning::config.yml not at jar root (check resources)"
fi

echo "== Velocity JAR =="
jar tf "$VEL_JAR" | grep -E 'velocity-plugin\.json$' \
  || { echo "::error::velocity-plugin.json missing"; exit 1; }
jar tf "$VEL_JAR" | grep -E 'dev/tienday/secureauth/velocity/SecureAuthVelocity\.class$' \
  || { echo "::error::SecureAuthVelocity.class missing"; exit 1; }
jar tf "$VEL_JAR" | grep -E 'dev/tienday/secureauth/velocity/AuthNotifyServer\.class$' \
  || { echo "::error::AuthNotifyServer.class missing"; exit 1; }

unzip -p "$VEL_JAR" velocity-plugin.json > "$TMP/velocity-plugin.json"
echo "--- velocity-plugin.json ---"
cat "$TMP/velocity-plugin.json"

grep -qE '"id"[[:space:]]*:[[:space:]]*"secureauth-velocity"' "$TMP/velocity-plugin.json" \
  || { echo "::error::velocity id incorrect"; exit 1; }
grep -qE '"main"[[:space:]]*:[[:space:]]*"dev\.tienday\.secureauth\.velocity\.SecureAuthVelocity"' "$TMP/velocity-plugin.json" \
  || { echo "::error::velocity main incorrect"; exit 1; }

echo "== Eggs (Pterodactyl) =="
if [ -d eggs ]; then
  for egg in eggs/*.json; do
    [ -f "$egg" ] || continue
    echo "Validate $egg"
    if command -v jq >/dev/null 2>&1; then
      jq -e '.name and .docker_images and .scripts' "$egg" >/dev/null \
        || { echo "::error::Invalid egg structure: $egg"; exit 1; }
      echo "  OK: $(jq -r .name "$egg")"
    else
      python3 -c "import json; d=json.load(open('$egg')); assert 'name' in d and 'docker_images' in d; print('  OK:', d['name'])"
    fi
  done
else
  echo "::warning::eggs/ folder missing"
fi

echo "== RESULT: JARs + version + eggs OK =="
echo "PAPER=$PAPER_JAR ($PAPER_SIZE)"
echo "VELOCITY=$VEL_JAR ($VEL_SIZE)"
echo "MC_API=$API_VER SUPPORTED=${SUPPORTED_MC[*]}"
