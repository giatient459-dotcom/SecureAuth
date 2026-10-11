package dev.tienday.secureauth.bungee;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.logging.Logger;

public final class PluginConfig {

    private final Properties props = new Properties();
    private final Logger logger;

    public PluginConfig(Path dataDir, Logger logger) {
        this.logger = logger;
        Path file = dataDir.resolve("config.properties");
        try {
            Files.createDirectories(dataDir);
            if (!Files.exists(file)) {
                copyDefault(file);
            }
            try (InputStream in = Files.newInputStream(file)) {
                props.load(in);
            }
        } catch (IOException e) {
            logger.severe("[SecureAuthBungee] Failed to load config: " + e.getMessage());
        }

        String secret = getBackendSecret();
        if (secret.isBlank() || secret.startsWith("CHANGE_ME")) {
            logger.warning("[SecureAuthBungee] backend-secret is default — change before production!");
        }
    }

    private void copyDefault(Path dest) throws IOException {
        try (InputStream in = getClass().getResourceAsStream("/config.properties")) {
            if (in != null) {
                try (OutputStream out = Files.newOutputStream(dest)) {
                    in.transferTo(out);
                }
            } else {
                Files.writeString(dest,
                        "http-port=20335\nhttp-bind=127.0.0.1\nbackend-secret=CHANGE_ME_SAME_AS_PAPER_SECRET\n"
                                + "auth-server=lobby\nsession-timeout-seconds=3600\n");
            }
        }
        logger.warning("[SecureAuthBungee] Created default " + dest + " — edit backend-secret!");
    }

    public int getHttpPort() {
        try {
            return Integer.parseInt(props.getProperty("http-port", "20335").trim());
        } catch (NumberFormatException e) {
            return 20335;
        }
    }

    public String getHttpBind() {
        String b = props.getProperty("http-bind", "127.0.0.1");
        return (b == null || b.isBlank()) ? "127.0.0.1" : b.trim();
    }

    public String getBackendSecret() {
        String s = props.getProperty("backend-secret", "");
        return s == null ? "" : s.trim();
    }

    public String getAuthServer() {
        String s = props.getProperty("auth-server", "");
        return s == null ? "" : s.trim();
    }

    public long getSessionTimeoutMs() {
        try {
            long sec = Long.parseLong(props.getProperty("session-timeout-seconds", "3600").trim());
            return sec <= 0 ? 0L : sec * 1000L;
        } catch (NumberFormatException e) {
            return 3600_000L;
        }
    }
}
