package dev.tienday.secureauth.util;

import dev.tienday.secureauth.SecureAuthPlugin;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

/**
 * Writes security audit events to plugins/SecureAuth/logs/audit-YYYY-MM-DD.log
 *
 * - Async write queue so logging never blocks the main thread
 * - Rotates by date automatically (new file each day)
 * - FIX: giữ file writer mở, không mở/đóng file mỗi dòng (giảm I/O cực mạnh)
 * - FIX: khi queue đầy → ghi đồng bộ (fallback), không mất log
 * - FIX: queue size tăng lên 16384 để chịu được burst
 * - No sensitive data (passwords / hashes) is ever written here
 */
public class AuditLogger {

    private static final DateTimeFormatter DATE_FMT      = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter DATETIME_FMT  = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** Queue size — FIX: tăng từ 4096 lên 16384. */
    private static final int QUEUE_CAPACITY = 16384;

    /** Sentinel để đánh thức writer thread khi stop. */
    private static final String SHUTDOWN_SENTINEL = "__SECUREAUTH_AUDIT_SHUTDOWN__";

    private final SecureAuthPlugin plugin;
    private final Path logDir;

    private final BlockingQueue<String> queue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
    private volatile boolean running = true;
    private Thread writerThread;

    /**
     * FIX: writer state — giữ file mở giữa các lần ghi.
     * Lock bảo vệ tất cả truy cập vào writer (writer thread + fallback sync path).
     */
    private final Object writerLock = new Object();
    private BufferedWriter currentWriter;
    private Path currentLogFile;

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
        queue.offer(SHUTDOWN_SENTINEL);  // unblock take()
        if (writerThread != null) {
            try {
                writerThread.join(3000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        // FIX: đóng file writer khi shutdown để flush hết buffer.
        synchronized (writerLock) {
            closeWriterQuietly();
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

    /**
     * FIX: khi queue đầy, ghi đồng bộ thay vì chỉ log console.
     * Trước đây log bị mất hoàn toàn khi queue full (burst attack, disk chậm).
     * Giờ ta có 3 lớp bảo vệ:
     *   1. Queue async (fast path)
     *   2. Sync fallback khi queue full (slow path nhưng vẫn giữ được log)
     *   3. Console warning nếu cả sync cũng fail
     */
    private void enqueue(String line) {
        if (queue.offer(line)) return;

        // Queue full — fallback ghi đồng bộ.
        plugin.getLogger().warning("[AuditLogger] Queue full ("
                + QUEUE_CAPACITY + "), writing synchronously");
        synchronized (writerLock) {
            try {
                writeLineLocked(line);
            } catch (IOException e) {
                plugin.getLogger().log(Level.SEVERE,
                        "[AuditLogger] Sync fallback ALSO failed, event lost: " + line, e);
            }
        }
    }

    private void writerLoop() {
        while (running || !queue.isEmpty()) {
            try {
                String line = queue.poll(1, TimeUnit.SECONDS);
                if (line == null) {
                    // FIX: kiểm tra date rotation khi idle.
                    synchronized (writerLock) {
                        try {
                            rotateIfNeededLocked();
                        } catch (IOException e) {
                            plugin.getLogger().log(Level.WARNING,
                                    "[AuditLogger] Rotation failed", e);
                        }
                    }
                    continue;
                }
                if (SHUTDOWN_SENTINEL.equals(line)) break;

                synchronized (writerLock) {
                    try {
                        writeLineLocked(line);
                    } catch (IOException e) {
                        plugin.getLogger().log(Level.WARNING,
                                "[AuditLogger] Disk write failed, event lost: " + line, e);
                        closeWriterQuietly();
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /**
     * Ghi một dòng — PHẢI gọi trong synchronized(writerLock).
     * FIX: chỉ mở file khi cần (lazy), giữ writer giữa các lần ghi.
     */
    private void writeLineLocked(String line) throws IOException {
        rotateIfNeededLocked();
        currentWriter.write(line);
        currentWriter.newLine();
        currentWriter.flush();
    }

    /**
     * Kiểm tra xem có cần chuyển sang file log của ngày mới không.
     * PHẢI gọi trong synchronized(writerLock).
     */
    private void rotateIfNeededLocked() throws IOException {
        Path target = logDir.resolve("audit-" + LocalDate.now().format(DATE_FMT) + ".log");
        if (currentWriter != null && target.equals(currentLogFile)) return;

        closeWriterQuietly();
        Files.createDirectories(logDir);
        currentWriter = Files.newBufferedWriter(
                target,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND);
        currentLogFile = target;
    }

    private void closeWriterQuietly() {
        if (currentWriter != null) {
            try { currentWriter.close(); } catch (IOException ignored) { }
            currentWriter = null;
        }
        currentLogFile = null;
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
