#!/usr/bin/env bash
# SecureAuth — Build Spigot jar để test compatibility
# Dùng:
#   chmod +x scripts/buildtools.sh
#   ./scripts/buildtools.sh
#   MC_VERSION=1.21.1 ./scripts/buildtools.sh
#   SKIP_BUILD=1 ./scripts/buildtools.sh   # chỉ test, không build lại
set -euo pipefail

# ============ CẤU HÌNH ============
MC_VERSION="${MC_VERSION:-1.21.4}"
WORK_DIR="${WORK_DIR:-.buildtools}"
BUILDTOOLS_URL="https://hub.spigotmc.org/jenkins/job/BuildTools/lastSuccessfulBuild/artifact/target/BuildTools.jar"
PLUGIN_JAR="${PLUGIN_JAR:-paper/target/SecureAuth-1.0.3.jar}"
TEST_SERVER_DIR="${TEST_SERVER_DIR:-.spigot-test}"

# ============ MÀU LOG ============
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ============ KIỂM TRA MÔI TRƯỜNG ============
command -v java >/dev/null 2>&1 || { log_error "java không có trong PATH"; exit 1; }
command -v git  >/dev/null 2>&1 || { log_error "git không có trong PATH";  exit 1; }

JAVA_VER=$(java -version 2>&1 | head -1 | sed -E 's/.*version "([0-9]+).*/\1/')
log_info "Java version: $JAVA_VER"
log_info "MC version:   $MC_VERSION"
log_info "Work dir:     $WORK_DIR"

# Spigot 1.21.x cần Java 21
if [ "$JAVA_VER" -lt 21 ] && [[ "$MC_VERSION" == 1.21* ]]; then
  log_error "Spigot $MC_VERSION cần Java 21, bạn đang dùng Java $JAVA_VER"
  exit 1
fi

# ============ TẢI BUILDTOOLS ============
mkdir -p "$WORK_DIR"
if [ ! -f "$WORK_DIR/BuildTools.jar" ]; then
  log_info "Downloading BuildTools.jar..."
  curl -fsSL -o "$WORK_DIR/BuildTools.jar" "$BUILDTOOLS_URL" \
    || { log_error "Không tải được BuildTools.jar"; exit 1; }
fi

# ============ BUILD SPIGOT ============
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  log_info "Bắt đầu build Spigot $MC_VERSION (10-30 phút, kiên nhẫn)..."
  cd "$WORK_DIR"
  # KHÔNG dùng --output-dir để tránh lặp path .buildtools/.buildtools/
  java -jar BuildTools.jar --rev "$MC_VERSION"
  cd ..
fi

# ============ TÌM FILE SPIGOT (TÊN LINH HOẠT) ============
SPIGOT_JAR=$(find "$WORK_DIR" -maxdepth 3 -name "spigot-${MC_VERSION}*.jar" -type f ! -name "*-bootstrap.jar" | head -1)

if [ -z "$SPIGOT_JAR" ]; then
  log_error "Không tìm thấy spigot-${MC_VERSION}*.jar trong $WORK_DIR"
  log_info "Các file .jar có trong $WORK_DIR:"
  find "$WORK_DIR" -name "*.jar" -type f
  exit 1
fi

log_info "Spigot JAR OK: $SPIGOT_JAR"
log_info "Size: $(stat -c%s "$SPIGOT_JAR") bytes"

# ============ CHUẨN BỊ TEST SERVER ============
mkdir -p "$TEST_SERVER_DIR/plugins"
cp "$SPIGOT_JAR" "$TEST_SERVER_DIR/spigot.jar"
echo "eula=true" > "$TEST_SERVER_DIR/eula.txt"

if [ ! -f "$PLUGIN_JAR" ]; then
  log_warn "Plugin JAR chưa có: $PLUGIN_JAR"
  log_info "Chạy: mvn clean verify (ở thư mục gốc) trước"
  exit 1
fi
cp "$PLUGIN_JAR" "$TEST_SERVER_DIR/plugins/"
log_info "Đã copy plugin vào $TEST_SERVER_DIR/plugins/"

# ============ HƯỚNG DẪN ============
cat <<EOF

=====================================================
BƯỚC TIẾP THEO — Test SecureAuth trên Spigot $MC_VERSION
=====================================================
Server test: $TEST_SERVER_DIR/

Chạy server:
  cd $TEST_SERVER_DIR && java -jar spigot.jar nogui

Test trong game:
  /register <pass> <pass>
  /login <pass>
  /authadmin info
  /uuid

Kiểm tra log console:
  - Dòng "SecureAuth" khi plugin load
  - Gõ /plugins trong game
=====================================================
EOF
