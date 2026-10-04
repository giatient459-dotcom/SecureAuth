package dev.tienday.secureauth.license;

import org.bukkit.plugin.java.JavaPlugin;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/**
 * HWID ổn định theo server data folder: sa-&lt;uuid&gt;
 * (giống log: sa-7b9a8eb2-e43c-490d-ba34-8d19d83f3e50)
 */
public final class HardwareFingerprint {

    private static final String FILE = "server-hwid.txt";

    private HardwareFingerprint() {}

    public static String getHwid(JavaPlugin plugin) {
        try {
            Path p = plugin.getDataFolder().toPath().resolve(FILE);
            if (Files.isRegularFile(p)) {
                String existing = Files.readString(p, StandardCharsets.UTF_8).trim();
                if (existing.startsWith("sa-") && existing.length() > 10) return existing;
            }
            Files.createDirectories(plugin.getDataFolder().toPath());
            String hwid = "sa-" + UUID.randomUUID();
            Files.writeString(p, hwid, StandardCharsets.UTF_8);
            return hwid;
        } catch (Exception e) {
            return "sa-" + UUID.nameUUIDFromBytes(
                    (System.getProperty("user.name", "u") + "|" + System.getProperty("os.name", "o"))
                            .getBytes(StandardCharsets.UTF_8));
        }
    }

    /** @deprecated dùng getHwid(plugin) */
    public static String getHwid() {
        return "sa-unknown";
    }
}
