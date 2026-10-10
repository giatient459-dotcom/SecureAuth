package dev.tienday.secureauth.util;

import dev.tienday.secureauth.SecureAuthPlugin;
import org.bstats.bukkit.Metrics;
import org.bstats.charts.SimplePie;
import org.bstats.charts.SingleLineChart;

import java.util.logging.Level;

/**
 * bStats — thống kê ẩn danh (plugin id 34505 hardcode).
 * Bật/tắt qua config: metrics.enabled
 */
public final class MetricsManager {

    private static final int PLUGIN_ID = 34505;

    private final SecureAuthPlugin plugin;
    private Metrics metrics;

    public MetricsManager(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public void start() {
        try {
            metrics = new Metrics(plugin, PLUGIN_ID);

            metrics.addCustomChart(new SimplePie("protocolib", () -> {
                try {
                    ProtocolHook hook = plugin.getProtocolHook();
                    return (hook != null && hook.isEnabled()) ? "yes" : "no";
                } catch (Exception e) {
                    return "unknown";
                }
            }));

            metrics.addCustomChart(new SimplePie("ip_session_enabled", () -> {
                try {
                    return plugin.getConfigManager().isIpSessionEnabled() ? "yes" : "no";
                } catch (Exception e) {
                    return "unknown";
                }
            }));

            metrics.addCustomChart(new SimplePie("webhook_enabled", () -> {
                try {
                    return plugin.getConfigManager().isWebhookEnabled() ? "yes" : "no";
                } catch (Exception e) {
                    return "unknown";
                }
            }));

            metrics.addCustomChart(new SimplePie("backup_enabled", () -> {
                try {
                    return plugin.getConfigManager().getBackupIntervalHours() > 0 ? "yes" : "no";
                } catch (Exception e) {
                    return "unknown";
                }
            }));

            metrics.addCustomChart(new SingleLineChart("registered_players", () -> {
                try {
                    return plugin.getDatabaseManager().listPlayers(1000).size();
                } catch (Exception e) {
                    return 0;
                }
            }));

            metrics.addCustomChart(new SimplePie("db_schema_version", () -> {
                try {
                    return String.valueOf(plugin.getDatabaseManager().getSchemaVersion());
                } catch (Exception e) {
                    return "unknown";
                }
            }));

            plugin.getLogger().info("[bStats] Metrics started (pluginId=" + PLUGIN_ID + ")");
        } catch (Throwable t) {
            plugin.getLogger().log(Level.WARNING, "[bStats] Failed to start metrics", t);
        }
    }

    public void shutdown() {
        metrics = null;
    }
}
