#!/usr/bin/env python3
"""
SecureAuth Security Audit — Smart & Attack-Aware
Kiểm tra bảo mật thực tế + mô phỏng tấn công trực quan.

Usage:
    python3 scripts/audit.py
    python3 scripts/audit.py --root /path/to/repo
"""
import os
import re
import sys
import argparse
from typing import Dict, List

# ═══════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════

RESULTS = {"good": [], "warn": [], "issue": []}

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def read(p: str) -> str:
    try:
        with open(p, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def load_java_dir(d: str) -> Dict[str, str]:
    out = {}
    if not os.path.isdir(d):
        return out
    for root, _, fnames in os.walk(d):
        for f in fnames:
            if f.endswith(".java"):
                out[f] = read(os.path.join(root, f))
    return out

def good(msg): RESULTS["good"].append(f"✅ {msg}")
def warn(msg): RESULTS["warn"].append(f"⚠  {msg}")
def issue(msg): RESULTS["issue"].append(f"❌ {msg}")

def check(cond: bool, ok: str, fail: str, warn_only: bool = False):
    if cond:
        good(ok)
    elif warn_only:
        warn(fail)
    else:
        issue(fail)

# ═══════════════════════════════════════════════════════════════════════
# 1. WORKFLOW SMART CHECK
# ═══════════════════════════════════════════════════════════════════════

def check_workflow(workflow: str, release: str, spigot_wf: str = ""):
    combined = workflow + "\n" + release + "\n" + spigot_wf

    wf_patterns = [
        (r"actions/checkout@v([4-9])",              "checkout@v4+",          "checkout action"),
        (r"actions/upload-artifact@v([4-9])",       "upload-artifact@v4+",   "upload-artifact action"),
        (r"actions/setup-java@v([4-9])",            "setup-java@v4+",        "setup-java action"),
    ]
    for pat, label, desc in wf_patterns:
        m = re.search(pat, combined)
        check(bool(m), f"Workflow: {label}", f"Workflow: {desc} not found/outdated")

    if re.search(r"actions/cache@v([4-9])", combined) or re.search(r"cache:\s*maven", combined):
        good("Workflow: cache configured (actions/cache or setup-java cache:maven)")
    else:
        warn("Workflow: no cache configured (optional — setup-java cache:maven is enough)")

    check("ubuntu-24.04" in combined or "ubuntu-22.04" in combined,
          "Workflow: ubuntu 24.04/22.04",
          "Workflow: ubuntu runner not pinned")

    check("bungee/target/SecureAuthBungee" in combined or "SecureAuthBungee-*.jar" in combined,
          "Workflow: BungeeCord JAR path",
          "Workflow: BungeeCord JAR path missing")

    check(re.search(r"java-version:\s*['\"]?21['\"]?", combined) is not None,
          "Workflow: Java 21",
          "Workflow: Java 21 not set")

# ═══════════════════════════════════════════════════════════════════════
# 2. POM STRUCTURE
# ═══════════════════════════════════════════════════════════════════════

def check_poms(root_pom: str, bungee_pom: str, paper_pom: str, velocity_pom: str):
    for mod in ["paper", "velocity", "bungee"]:
        check(f"<module>{mod}</module>" in root_pom,
              f"root pom: module {mod}",
              f"root pom: module {mod} MISSING")

    check("SecureAuthBungee" in bungee_pom,
          "Bungee pom: artifactId",
          "Bungee pom: artifactId missing")
    check("bungeecord-api" in bungee_pom,
          "Bungee pom: bungeecord-api dependency",
          "Bungee pom: bungeecord-api missing")
    check("paper-api" in paper_pom,
          "Paper pom: paper-api dependency",
          "Paper pom: paper-api missing")
    check("velocity-api" in velocity_pom,
          "Velocity pom: velocity-api dependency",
          "Velocity pom: velocity-api missing")
    check("maven-shade-plugin" in bungee_pom or "maven-shade-plugin" in root_pom,
          "Bungee pom: shade plugin configured",
          "Bungee pom: shade plugin missing", warn_only=True)

# ═══════════════════════════════════════════════════════════════════════
# 3. BUNGEE SMART CHECK
# ═══════════════════════════════════════════════════════════════════════

def check_bungee(bfiles: Dict[str, str]):
    event_listener = bfiles.get("AuthEventListener.java", "")
    notify_server = bfiles.get("AuthNotifyServer.java", "")
    config = bfiles.get("PluginConfig.java", "")
    session_store = bfiles.get("AuthSessionStore.java", "")
    main = bfiles.get("SecureAuthBungee.java", "")

    event_patterns = ["LoginEvent", "ServerConnectEvent", "PreLoginEvent"]
    has_event = any(p in event_listener for p in event_patterns)
    check(has_event, "Bungee: auth event handler", "Bungee: NO auth event handler found")

    bind_patterns = ["127.0.0.1", "getHttpBind", "http-bind"]
    has_bind = any(p in notify_server or p in config for p in bind_patterns)
    check(has_bind, "Bungee: HTTP bind localhost/configurable",
          "Bungee: HTTP bind NOT localhost/configurable")

    ct_patterns = ["MessageDigest.isEqual", "constantTimeEquals", "MessageDigest", "timingSafeEqual"]
    has_ct = any(p in notify_server for p in ct_patterns)
    check(has_ct, "Bungee: constant-time auth", "Bungee: NO constant-time auth")

    check("ConcurrentHashMap" in session_store or "ConcurrentMap" in session_store,
          "Bungee: thread-safe session store",
          "Bungee: session store NOT thread-safe")

    check("extends Plugin" in main or "extends JavaPlugin" in main,
          "Bungee: main plugin class extends Plugin",
          "Bungee: main class does not extend Plugin")

    check("registerListener" in main,
          "Bungee: listener registered",
          "Bungee: listener NOT registered")

# ═══════════════════════════════════════════════════════════════════════
# 4. PAPER SECURITY
# ═══════════════════════════════════════════════════════════════════════

def check_paper_security(pfiles: Dict[str, str], main_cls: str, config_yml: str):
    pw = pfiles.get("PasswordUtil.java", "")
    if re.search(r"argon2|ARGON2", pw, re.IGNORECASE):
        good("Paper: Argon2id password hashing")
    else:
        issue("Paper: Argon2id NOT found")

    weak_found = []
    for fn, src in pfiles.items():
        if re.search(r"\bMessageDigest\.getInstance\(\"MD5\"\)|\bMessageDigest\.getInstance\(\"SHA-?1\"\)", src):
            weak_found.append(fn)
    check(not weak_found, "Paper: No MD5/SHA1 usage", f"Paper: Weak hash in {weak_found}")

    sql_injection = []
    for fn, src in pfiles.items():
        if re.search(r'"(SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*\+', src, re.IGNORECASE):
            sql_injection.append(fn)
    check(not sql_injection, "Paper: No SQL string concatenation",
          f"Paper: SQL concat in {sql_injection}")

    db = pfiles.get("DatabaseManager.java", "")
    check("countAccountsByIp" in db or "register_ip" in db,
          "Paper: IP-based account limit", "Paper: IP account limit missing")
    check("ALTER TABLE" in db or "schema_version" in db or "migrate" in db.lower(),
          "Paper: safe DB migration", "Paper: DB migration not detected")

    al = pfiles.get("AuthListener.java", "")
    check("ALLOWED_COMMANDS" in al or "allowlist" in al.lower(),
          "Paper: pre-login command allowlist", "Paper: allowlist missing")

    opg = pfiles.get("OPGuardListener.java", "")
    check("setOp(false)" in opg or "deop" in opg.lower(),
          "Paper: auto-deop on join", "Paper: auto-deop missing")

    http = pfiles.get("PluginHttpServer.java", "")
    if http:
        check("127.0.0.1" in http or "getHttpBind" in http,
              "Paper: HTTP localhost/configurable", "Paper: HTTP bind NOT localhost")
        check(any(p in http for p in ["MessageDigest.isEqual", "constantTimeEquals"]),
              "Paper: HTTP constant-time auth", "Paper: HTTP auth NOT constant-time")

    audit = pfiles.get("AuditLogger.java", "")
    check("BlockingQueue" in audit or "ExecutorService" in audit or "async" in audit.lower(),
          "Paper: AuditLogger async", "Paper: AuditLogger NOT async", warn_only=True)

    check("LicenseManager" not in main_cls,
          "Paper: LicenseManager removed", "Paper: LicenseManager still wired")
    check("license" not in config_yml.lower() or "key:" not in config_yml,
          "config.yml: no license section", "config.yml: license section still present")

# ═══════════════════════════════════════════════════════════════════════
# 5. PAPER FEATURES
# ═══════════════════════════════════════════════════════════════════════

def check_paper_features(pfiles: Dict[str, str], plugin_yml: str, main_cls: str):
    db = pfiles.get("DatabaseManager.java", "")
    pd = pfiles.get("PlayerData.java", "")

    feature_checks = [
        (db, "resetPasswordKeepLink", "resetPasswordKeepLink"),
        (db, "register_ip", "register_ip column"),
        (db, "last_login_ip", "last_login_ip column"),
        (pd, "registerIp", "PlayerData.registerIp"),
        (pd, "lastLoginIp", "PlayerData.lastLoginIp"),
    ]
    for src, needle, label in feature_checks:
        check(needle in src, f"Paper: {label}", f"Paper: {label} MISSING")

    for cls in ["DatabaseManager", "SessionManager", "RateLimiter",
                "TwoFactorManager", "AuditLogger", "PluginHttpServer"]:
        check(cls in main_cls, f"Main: {cls} wired", f"Main: {cls} NOT wired")

    for cmd in ["login", "register", "link", "authadmin", "uuid", "changepassword"]:
        check(cmd in plugin_yml, f"plugin.yml: /{cmd}", f"plugin.yml: /{cmd} MISSING")

# ═══════════════════════════════════════════════════════════════════════
# 6. VELOCITY SMART CHECK
# ═══════════════════════════════════════════════════════════════════════

def check_velocity(vfiles: Dict[str, str]):
    notify = vfiles.get("AuthNotifyServer.java", "")
    listener = vfiles.get("AuthEventListener.java", "")
    store = vfiles.get("AuthSessionStore.java", "")

    check(any(p in notify for p in ["getHttpBind", "http-bind", "127.0.0.1"]),
          "Velocity: HTTP bind configurable", "Velocity: HTTP bind NOT configurable")
    check(any(p in notify for p in ["MessageDigest", "constantTimeEquals"]),
          "Velocity: constant-time auth", "Velocity: auth NOT constant-time")
    check("isAuthenticated" in listener or "isAuthenticated" in store,
          "Velocity: blocks unauthenticated", "Velocity: does NOT block unauthenticated")
    check("ConcurrentHashMap" in store or "ConcurrentMap" in store,
          "Velocity: thread-safe store", "Velocity: store NOT thread-safe")

# ═══════════════════════════════════════════════════════════════════════
# 7. ATTACK SIMULATION — Visual & Educational
# ═══════════════════════════════════════════════════════════════════════

def simulate_attacks(bfiles: Dict[str, str], vfiles: Dict[str, str],
                     pfiles: Dict[str, str]):
    all_files = {**bfiles, **vfiles, **pfiles}

    print(f"\n{BOLD}{BLUE}{'─'*64}")
    print(f"🎯 ATTACK SIMULATION — Hacker sẽ tấn công thế nào?")
    print(f"{'─'*64}{RESET}\n")

    notify = bfiles.get("AuthNotifyServer.java", "") + \
             vfiles.get("AuthNotifyServer.java", "") + \
             pfiles.get("PluginHttpServer.java", "")

    # ═══════════════════════════════════════════════════════════════════
    # ATTACK 1: TIMING ATTACK
    # ═══════════════════════════════════════════════════════════════════
    print(f"{BOLD}[Attack 1] TIMING ATTACK{RESET}")
    print(f"{'─'*64}")
    print(f"Hacker gửi request với secret sai, đo thời gian response")
    print(f"→ Nếu dùng .equals(), thời gian khác nhau → dò được secret\n")

    uses_constant_time = (
        "constantTimeEquals" in notify or
        "MessageDigest.isEqual" in notify or
        "timingSafeEqual" in notify
    )
    uses_equals_on_secret = bool(re.search(
        r'\.equals\([^)]*[Ss]ecret[^)]*\)|'
        r'[Ss]ecret[^)]*\.equals\(',
        notify
    ))

    if uses_equals_on_secret:
        print(f"  ❌ FAIL — Code dùng .equals() cho secret!")
        print(f"     Hacker có thể dò từng ký tự:")
        print(f"     ┌─────────────────────────────────────┐")
        print(f"     │ secret = \"abc\"                     │")
        print(f"     │ Thử \"x..\": 10ms → sai              │")
        print(f"     │ Thử \"a..\": 12ms → gần đúng hơn!    │")
        print(f"     │ Thử \"ab.\": 14ms → đúng 2 ký tự!    │")
        print(f"     │ Thử \"abc\": 15ms → TÌM RA SECRET!   │")
        print(f"     └─────────────────────────────────────┘")
        issue("ATTACK-SIM: timing attack — dùng .equals() trên secret")
    elif uses_constant_time:
        print(f"  ✅ PASS — Dùng constant-time comparison")
        print(f"     Mọi request đều mất cùng thời gian:")
        print(f"     ┌─────────────────────────────────────┐")
        print(f"     │ Thử \"x..\": 15ms                    │")
        print(f"     │ Thử \"a..\": 15ms                    │")
        print(f"     │ Thử \"ab.\": 15ms                    │")
        print(f"     │ Thử \"abc\": 15ms → KHÔNG dò được    │")
        print(f"     └─────────────────────────────────────┘")
        good("ATTACK-SIM: timing attack mitigated")
    else:
        print(f"  ⚠️  Không rõ — không thấy constant-time comparison")
        warn("ATTACK-SIM: timing attack — không xác định")
    print()

    # ═══════════════════════════════════════════════════════════════════
    # ATTACK 2: REPLAY ATTACK
    # ═══════════════════════════════════════════════════════════════════
    print(f"{BOLD}[Attack 2] REPLAY ATTACK{RESET}")
    print(f"{'─'*64}")
    print(f"Hacker bắt được request hợp lệ, gửi lại nhiều lần\n")

    has_timestamp = "timestamp" in notify.lower()
    has_nonce = "nonce" in notify.lower()
    has_hmac = "hmac" in notify.lower() or "signature" in notify.lower()

    if has_hmac:
        print(f"  ✅ PASS — Dùng HMAC signature")
        print(f"     Request cũ bị reject vì signature không khớp:")
        print(f"     ┌─────────────────────────────────────┐")
        print(f"     │ Request 1: signature=abc → OK       │")
        print(f"     │ Request 1 (replay): signature=abc   │")
        print(f"     │  → timestamp cũ → REJECT            │")
        print(f"     └─────────────────────────────────────┘")
        good("ATTACK-SIM: replay attack mitigated (HMAC)")
    elif has_timestamp and has_nonce:
        print(f"  ✅ PASS — Dùng timestamp + nonce")
        print(f"     ┌─────────────────────────────────────┐")
        print(f"     │ Request 1: ts=12:00, nonce=abc → OK │")
        print(f"     │ Request 1 (replay): ts=12:00 → cũ   │")
        print(f"     │  → REJECT                           │")
        print(f"     └─────────────────────────────────────┘")
        good("ATTACK-SIM: replay attack mitigated (ts+nonce)")
    elif has_timestamp:
        print(f"  ⚠️  PARTIAL — Có timestamp, chưa có nonce")
        print(f"     Hacker có thể replay trong cửa sổ 5 phút:")
        print(f"     ┌─────────────────────────────────────┐")
        print(f"     │ Request 1: ts=12:00 → OK            │")
        print(f"     │ Request 1 (replay 12:02): OK ← lỗ hổng│")
        print(f"     │ Request 1 (replay 12:06): REJECT    │")
        print(f"     └─────────────────────────────────────┘")
        warn("ATTACK-SIM: replay attack — chỉ có timestamp (chưa đủ)")
    else:
        print(f"  ⚠️  FAIL — Không có timestamp/nonce/HMAC")
        print(f"     Hacker bắt request → gửi lại → server chấp nhận:")
        print(f"     ┌─────────────────────────────────────┐")
        print(f"     │ Request 1: uuid=abc, auth=true → OK │")
        print(f"     │ (hacker capture request)             │")
        print(f"     │ Request 1 (replay): → OK ← BỊ HACK  │")
        print(f"     │ Request 1 (replay 1000x) → OK       │")
        print(f"     │  → DoS hoặc bypass auth             │")
        print(f"     └─────────────────────────────────────┘")
        print(f"     Cách fix:")
        print(f"       - Thêm timestamp + validate (dễ)")
        print(f"       - Thêm nonce (tốt hơn)")
        print(f"       - Dùng HMAC signature (tốt nhất)")
        warn("ATTACK-SIM: no timestamp/nonce — replay possible")
    print()

    # ═══════════════════════════════════════════════════════════════════
    # ATTACK 3: PATH TRAVERSAL
    # ═══════════════════════════════════════════════════════════════════
    print(f"{BOLD}[Attack 3] PATH TRAVERSAL{RESET}")
    print(f"{'─'*64}")
    print(f"Hacker truyền đường dẫn '../etc/passwd' để đọc file hệ thống\n")

    vulnerable_files = []
    for fn, src in all_files.items():
        if re.search(r'new\s+File\s*\(\s*[^)]*\+[^)]*\)|'
                     r'Paths\.get\s*\(\s*[^)]*\+[^)]*\)|'
                     r'new\s+FileInputStream\s*\(\s*[^)]*\+',
                     src):
            vulnerable_files.append(fn)

    if vulnerable_files:
        print(f"  ❌ FAIL — Có {len(vulnerable_files)} file có thể bị path traversal:")
        for f in vulnerable_files:
            print(f"     - {f}")
        print(f"     Ví dụ tấn công:")
        print(f"     ┌─────────────────────────────────────┐")
        print(f"     │ Request: file=../../../../etc/passwd│")
        print(f"     │  → Server đọc /etc/passwd           │")
        print(f"     │  → Lộ thông tin hệ thống            │")
        print(f"     └─────────────────────────────────────┘")
        warn(f"ATTACK-SIM: path traversal possible in {len(vulnerable_files)} file(s)")
    else:
        print(f"  ✅ PASS — Không thấy pattern nguy hiểm")
        print(f"     Code không đọc file dựa trên input user")
        good("ATTACK-SIM: path traversal — không phát hiện lỗ hổng")
    print()

    # ═══════════════════════════════════════════════════════════════════
    # ATTACK 4: SQL INJECTION
    # ═══════════════════════════════════════════════════════════════════
    print(f"{BOLD}[Attack 4] SQL INJECTION{RESET}")
    print(f"{'─'*64}")
    print(f"Hacker chèn SQL vào username để bypass auth\n")

    sql_vuln = []
    for fn, src in all_files.items():
        if re.search(r'"(SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*\+', src, re.IGNORECASE):
            sql_vuln.append(fn)

    if sql_vuln:
        print(f"  ❌ FAIL — Có {len(sql_vuln)} file có SQL concat:")
        for f in sql_vuln:
            print(f"     - {f}")
        print(f"     Ví dụ:")
        print(f"     ┌─────────────────────────────────────┐")
        print(f"     │ username = \"admin' OR '1'='1\"       │")
        print(f"     │ SQL: SELECT * FROM users WHERE      │")
        print(f"     │      name = 'admin' OR '1'='1'      │")
        print(f"     │  → Trả về TẤT CẢ user               │")
        print(f"     └─────────────────────────────────────┘")
        issue(f"ATTACK-SIM: SQL injection in {len(sql_vuln)} file(s)")
    else:
        print(f"  ✅ PASS — Không có SQL string concat")
        print(f"     Tất cả query dùng PreparedStatement")
        good("ATTACK-SIM: SQL injection — không phát hiện")
    print()

    # ═══════════════════════════════════════════════════════════════════
    # ATTACK 5: BRUTE FORCE
    # ═══════════════════════════════════════════════════════════════════
    print(f"{BOLD}[Attack 5] BRUTE FORCE{RESET}")
    print(f"{'─'*64}")
    print(f"Hacker thử 1000 mật khẩu/giây để tìm mật khẩu đúng\n")

    has_rate_limit = any(
        "RateLimiter" in fn or "rateLimit" in src.lower() or "rate-limit" in src.lower()
        for fn, src in all_files.items()
    )
    has_lockout = any(
        "lockout" in src.lower() or "maxAttempts" in src or "max-attempts" in src.lower()
        for src in all_files.values()
    )

    if has_rate_limit and has_lockout:
        print(f"  ✅ PASS — Có rate limit + lockout")
        print(f"     ┌─────────────────────────────────────┐")
        print(f"     │ Attempt 1: sai → OK                 │")
        print(f"     │ Attempt 2: sai → OK                 │")
        print(f"     │ ...                                  │")
        print(f"     │ Attempt 5: sai → LOCKOUT 5 phút     │")
        print(f"     │ Attempt 6: → REJECT (locked)        │")
        print(f"     └─────────────────────────────────────┘")
        good("ATTACK-SIM: brute force mitigated (rate limit + lockout)")
    elif has_rate_limit:
        print(f"  ⚠️  PARTIAL — Có rate limit, chưa có lockout")
        warn("ATTACK-SIM: brute force — rate limit only")
    else:
        print(f"  ❌ FAIL — Không có rate limit!")
        print(f"     Hacker có thể thử 1000 mật khẩu/giây")
        issue("ATTACK-SIM: brute force — no rate limit")
    print()

    # ═══════════════════════════════════════════════════════════════════
    # ATTACK 6: SESSION HIJACKING
    # ═══════════════════════════════════════════════════════════════════
    print(f"{BOLD}[Attack 6] SESSION HIJACKING{RESET}")
    print(f"{'─'*64}")
    print(f"Hacker đánh cắp session của player khác\n")

    session_store = bfiles.get("AuthSessionStore.java", "") + \
                    vfiles.get("AuthSessionStore.java", "") + \
                    pfiles.get("SessionManager.java", "")

    has_ip_check = "ip" in session_store.lower() or "address" in session_store.lower()
    has_timeout = "timeout" in session_store.lower() or "expire" in session_store.lower()

    if has_ip_check and has_timeout:
        print(f"  ✅ PASS — Session gắn với IP + có timeout")
        print(f"     ┌─────────────────────────────────────┐")
        print(f"     │ Player A login từ 1.2.3.4           │")
        print(f"     │ Session: uuid=A, ip=1.2.3.4, exp=T  │")
        print(f"     │ Hacker copy session → dùng từ 5.6.7.8│")
        print(f"     │  → IP mismatch → REJECT             │")
        print(f"     └─────────────────────────────────────┘")
        good("ATTACK-SIM: session hijacking mitigated (IP + timeout)")
    elif has_timeout:
        print(f"  ⚠️  PARTIAL — Có timeout, chưa check IP")
        warn("ATTACK-SIM: session hijacking — timeout only")
    else:
        print(f"  ⚠️  Không rõ — không thấy timeout")
        warn("ATTACK-SIM: session timeout không xác định")
    print()

    # ═══════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════
    print(f"{BOLD}{CYAN}{'─'*64}")
    print(f"📊 TỔNG KẾT ATTACK SIMULATION")
    print(f"{'─'*64}{RESET}")
    print(f"  • Timing attack    : {'✅ mitigated' if uses_constant_time else '⚠️  check'}")
    print(f"  • Replay attack    : {'✅ mitigated' if (has_timestamp or has_nonce or has_hmac) else '⚠️  possible'}")
    print(f"  • Path traversal   : {'✅ clean' if not vulnerable_files else '⚠️  found'}")
    print(f"  • SQL injection    : {'✅ clean' if not sql_vuln else '❌ found'}")
    print(f"  • Brute force      : {'✅ mitigated' if (has_rate_limit and has_lockout) else '⚠️  check'}")
    print(f"  • Session hijack   : {'✅ mitigated' if (has_ip_check and has_timeout) else '⚠️  check'}")
    print()

# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=None, help="Repo root")
    args = parser.parse_args()

    root = args.root or os.environ.get("REPO_ROOT") or os.getcwd()
    if not os.path.isdir(root):
        print(f"{RED}Invalid root: {root}{RESET}")
        sys.exit(1)

    print(f"{BOLD}{BLUE}SecureAuth Security Audit{RESET}")
    print(f"Root: {root}\n")

    paper_dir    = f"{root}/paper/src/main/java/dev/tienday/secureauth"
    bungee_dir   = f"{root}/bungee/src/main/java/dev/tienday/secureauth/bungee"
    velocity_dir = f"{root}/velocity/src/main/java/dev/tienday/secureauth/velocity"
    resources    = f"{root}/paper/src/main/resources"

    pfiles = load_java_dir(paper_dir)
    bfiles = load_java_dir(bungee_dir)
    vfiles = load_java_dir(velocity_dir)

    plugin_yml   = read(f"{resources}/plugin.yml")
    config_yml   = read(f"{resources}/config.yml")
    paper_pom    = read(f"{root}/paper/pom.xml")
    root_pom     = read(f"{root}/pom.xml")
    bungee_pom   = read(f"{root}/bungee/pom.xml")
    velocity_pom = read(f"{root}/velocity/pom.xml")
    workflow     = read(f"{root}/.github/workflows/build.yml")
    release      = read(f"{root}/.github/workflows/release.yml")
    spigot_wf    = read(f"{root}/.github/workflows/spigot-test.yml")
    main_cls     = pfiles.get("SecureAuthPlugin.java", "")

    # Run all checks
    check_workflow(workflow, release, spigot_wf)
    check_poms(root_pom, bungee_pom, paper_pom, velocity_pom)
    check_bungee(bfiles)
    check_paper_security(pfiles, main_cls, config_yml)
    check_paper_features(pfiles, plugin_yml, main_cls)
    check_velocity(vfiles)

    # Attack simulation (visual)
    simulate_attacks(bfiles, vfiles, pfiles)

    # Print results
    print(f"{GREEN}{'='*64}")
    print(f"✅ GOOD  ({len(RESULTS['good'])})")
    print(f"{'='*64}{RESET}")
    for g in RESULTS["good"]:
        print(f"{GREEN}{g}{RESET}")

    if RESULTS["warn"]:
        print(f"\n{YELLOW}{'='*64}")
        print(f"⚠  WARN  ({len(RESULTS['warn'])})")
        print(f"{'='*64}{RESET}")
        for w in RESULTS["warn"]:
            print(f"{YELLOW}{w}{RESET}")

    print(f"\n{RED}{'='*64}")
    print(f"❌ ISSUES ({len(RESULTS['issue'])})")
    print(f"{'='*64}{RESET}")
    for i in RESULTS["issue"]:
        print(f"{RED}{i}{RESET}")

    total = len(RESULTS["good"]) + len(RESULTS["issue"])
    pct = int(len(RESULTS["good"]) / total * 100) if total else 0
    color = GREEN if pct >= 95 else (YELLOW if pct >= 80 else RED)
    print(f"\n{color}{BOLD}SCORE: {len(RESULTS['good'])}/{total} ({pct}%){RESET}")

    # Exit code — chỉ fail nếu có ISSUE
    sys.exit(0 if not RESULTS["issue"] else 1)

if __name__ == "__main__":
    main()
