package dev.tienday.secureauth.license;

import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSource;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;

/**
 * Kiểm tra hash JAR (tùy chọn).
 * Expected hash để trống = bỏ qua.
 * Bypass: -Dsecureauth.dev=true hoặc -Dplugin.dev=true
 */
public final class AntiTamper {

    private AntiTamper() {}

    public static boolean isDevMode() {
        return Boolean.parseBoolean(System.getProperty("secureauth.dev", "false"))
                || Boolean.parseBoolean(System.getProperty("plugin.dev", "false"));
    }

    /**
     * @param expectedSha256Hex hash mong đợi (64 hex) hoặc null/blank = skip
     * @return true nếu OK hoặc skip; false nếu lệch hash
     */
    public static boolean verifyJar(Class<?> anchor, String expectedSha256Hex, java.util.logging.Logger log) {
        if (isDevMode()) {
            if (log != null) log.info("[License] AntiTamper skipped (dev mode)");
            return true;
        }
        if (expectedSha256Hex == null || expectedSha256Hex.isBlank()) {
            return true; // chưa cấu hình hash → không chặn
        }
        try {
            Path jar = locateJar(anchor);
            if (jar == null || !Files.isRegularFile(jar)) {
                if (log != null) log.warning("[License] AntiTamper: cannot locate plugin JAR");
                return true; // không chặn nếu không tìm thấy (dev/IDE)
            }
            byte[] all = Files.readAllBytes(jar);
            String actual = CryptoUtils.toHex(CryptoUtils.sha256(all));
            if (!actual.equalsIgnoreCase(expectedSha256Hex.trim())) {
                if (log != null) {
                    log.warning("[License] AntiTamper: JAR hash mismatch");
                    log.warning("[License] expected=" + expectedSha256Hex);
                    log.warning("[License] actual  =" + actual);
                }
                return false;
            }
            return true;
        } catch (Exception e) {
            if (log != null) log.warning("[License] AntiTamper error: " + e.getMessage());
            return true; // lỗi đọc → không crash server
        }
    }

    private static Path locateJar(Class<?> anchor) {
        try {
            CodeSource cs = anchor.getProtectionDomain().getCodeSource();
            if (cs == null) return null;
            URL loc = cs.getLocation();
            if (loc == null) return null;
            return Path.of(loc.toURI());
        } catch (Exception e) {
            return null;
        }
    }
}
