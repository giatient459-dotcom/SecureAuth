package dev.tienday.secureauth.util;

import dev.tienday.secureauth.SecureAuthPlugin;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;

/**
 * Writes security audit events to plugins/SecureAuth/logs/audit-YYYY-MM-DD.log
 *
 * - Async write queue so logging never blocks the main thread
 * - Rotates by date automatically (new file each day)
 * - Falls back gracefully if disk write fails (still logs to console)
 * - No sensitive data (passwords / hashes) is ever written here
 */
public class AuditLogger {

    private static final DateTimeFormatter DATE_FMT      = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter DATETIME_FMT  = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final SecureAuthPlugin plugin;
    private final Path logDir;

    // Async queue — main thread enqueues, writer thread flushes
    private final BlockingQueue<String> queue = new LinkedBlockingQueue<>(4096);
    private volatile boolean running = true;
    private Thread writerThread;

    public AuditLogger(SecureAuthPlugin plugin) {
        this.plugin = plugin;
        this.logDir = plugin.getDataFolder().toPath().resolve("logs");
    }

    public void start() {
        try {
            Files.createDirectories(logDir);
        } catch (IOException e) {
            plugin.getLogger().log(Level.SEVERE, "Cannot create audit log directory", e);
        }

        writerThread = new Thread(this::writerLoop, "SecureAuth-AuditLog");
        writerThread.setDaemon(true);
        writerThread.start();
        plugin.getLogger().info("[AuditLogger] Started — logs at: " + logDir.toAbsolutePath());
    }

    public void stop() {
        running = false;
        queue.offer("__SHUTDOWN__");  // unblock take()
        try {
            writerThread.join(3000);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    // ── Public logging API ────────────────────────────────────────────────────

    /** Log a security event. Never pass passwords or hashes here. */
    public void log(String eventType, String playerName, String uuid,
                    String ip, String detail) {
        String line = String.format("[%s] [%s] player=%s uuid=%s ip=%s detail=%s",
                LocalDateTime.now().format(DATETIME_FMT),
                eventType,
                sanitize(playerName),
                sanitize(uuid),
                sanitize(ip),
                sanitize(detail));
        enqueue(line);
    }

    /** Shorthand for events without a specific player. */
    public void logSystem(String eventType, String detail) {
        String line = String.format("[%s] [%s] detail=%s",
                LocalDateTime.now().format(DATETIME_FMT),
                eventType,
                sanitize(detail));
        enqueue(line);
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    private void enqueue(String line) {
        if (!queue.offer(line)) {
            // Queue full — log to console at minimum
            plugin.getLogger().warning("[AuditLogger QUEUE FULL] " + line);
        }
    }

    private void writerLoop() {
        while (running || !queue.isEmpty()) {
            try {
                String line = queue.take();
                if ("__SHUTDOWN__".equals(line)) break;

                Path logFile = logDir.resolve("audit-" + LocalDate.now().format(DATE_FMT) + ".log");
                try (BufferedWriter writer = Files.newBufferedWriter(
                        logFile,
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.APPEND)) {
                    writer.write(line);
                    writer.newLine();
                } catch (IOException e) {
                    plugin.getLogger().log(Level.WARNING,
                            "[AuditLogger] Disk write failed, event lost to file: " + line, e);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /**
     * Strip newlines and control chars from any string before writing to log.
     * Prevents log injection (CRLF injection attacks).
     */
    private String sanitize(String input) {
        if (input == null) return "null";
        return input.replaceAll("[\r\n\t]", "_").replaceAll("[\\p{Cntrl}]", "?");
    }
}
