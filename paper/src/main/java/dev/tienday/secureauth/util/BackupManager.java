package dev.tienday.secureauth.util;

import dev.tienday.secureauth.SecureAuthPlugin;
import org.bukkit.scheduler.BukkitTask;

import java.io.IOException;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.logging.Level;
import java.util.stream.Stream;

/**
 * Copies secureauth.db to plugins/SecureAuth/backups/.
 * Manual via /authadmin backup; optional scheduled interval.
 */
public final class BackupManager {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private final SecureAuthPlugin plugin;
    private BukkitTask scheduledTask;

    public BackupManager(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public void startScheduled() {
        int hours = plugin.getConfigManager().getBackupIntervalHours();
        if (hours <= 0) return;
        long ticks = hours * 60L * 60L * 20L;
        scheduledTask = plugin.getServer().getScheduler().runTaskTimerAsynchronously(
                plugin, () -> {
                    try {
                        Path p = backupNow();
                        if (p != null) {
                            plugin.getLogger().info("[SecureAuth] Auto-backup: " + p.getFileName());
                            prune();
                        }
                    } catch (Exception e) {
                        plugin.getLogger().log(Level.WARNING, "Auto-backup failed", e);
                    }
                }, ticks, ticks);
    }

    public void shutdown() {
        if (scheduledTask != null) {
            scheduledTask.cancel();
            scheduledTask = null;
        }
    }

    /** @return path of new backup, or null on failure */
    public Path backupNow() throws IOException {
        Path data = plugin.getDataFolder().toPath();
        Path db = data.resolve("secureauth.db");
        if (!Files.exists(db)) {
            throw new IOException("secureauth.db not found");
        }
        Path dir = data.resolve("backups");
        Files.createDirectories(dir);
        String name = "secureauth-" + LocalDateTime.now().format(FMT) + ".db";
        Path dest = dir.resolve(name);
        // Also copy WAL/SHM if present for consistency
        Files.copy(db, dest, StandardCopyOption.REPLACE_EXISTING);
        Path wal = data.resolve("secureauth.db-wal");
        Path shm = data.resolve("secureauth.db-shm");
        if (Files.exists(wal)) {
            Files.copy(wal, dir.resolve(name + "-wal"), StandardCopyOption.REPLACE_EXISTING);
        }
        if (Files.exists(shm)) {
            Files.copy(shm, dir.resolve(name + "-shm"), StandardCopyOption.REPLACE_EXISTING);
        }
        return dest;
    }

    public void prune() {
        int keep = plugin.getConfigManager().getBackupKeepCount();
        if (keep <= 0) return;
        Path dir = plugin.getDataFolder().toPath().resolve("backups");
        if (!Files.isDirectory(dir)) return;
        try (Stream<Path> stream = Files.list(dir)) {
            stream.filter(p -> p.getFileName().toString().endsWith(".db"))
                    .sorted(Comparator.comparingLong((Path p) -> {
                        try { return Files.getLastModifiedTime(p).toMillis(); }
                        catch (IOException e) { return 0L; }
                    }).reversed())
                    .skip(keep)
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                            Files.deleteIfExists(Path.of(p.toString() + "-wal"));
                            Files.deleteIfExists(Path.of(p.toString() + "-shm"));
                        } catch (IOException ignored) {}
                    });
        } catch (IOException e) {
            plugin.getLogger().log(Level.WARNING, "Backup prune failed", e);
        }
    }
}
