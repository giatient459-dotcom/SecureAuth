package dev.tienday.secureauth.velocity;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

@Plugin(
        id = "secureauth-velocity",
        name = "SecureAuthVelocity",
        version = "1.0.1",
        authors = {"TienDay"},
        description = "Velocity companion for SecureAuth"
)
public final class SecureAuthVelocity {

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;

    private PluginConfig pluginConfig;
    private AuthSessionStore sessionStore;
    private AuthNotifyServer notifyServer;
    private ScheduledTask cleanupTask;

    @Inject
    public SecureAuthVelocity(ProxyServer server, Logger logger,
                              @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onInit(ProxyInitializeEvent event) {
        pluginConfig = new PluginConfig(dataDirectory, logger);
        sessionStore = new AuthSessionStore(pluginConfig.getSessionTimeoutMs());
        notifyServer = new AuthNotifyServer(this);

        server.getEventManager().register(this, new AuthEventListener(this));
        notifyServer.start();

        if (pluginConfig.getSessionTimeoutMs() > 0) {
            cleanupTask = server.getScheduler()
                    .buildTask(this, sessionStore::clearExpired)
                    .repeat(5, TimeUnit.MINUTES)
                    .schedule();
        }

        logger.info("SecureAuthVelocity 1.0.1 enabled — notify {}:{}",
                pluginConfig.getHttpBind(), pluginConfig.getHttpPort());
    }

    @Subscribe
    public void onShutdown(ProxyShutdownEvent event) {
        if (cleanupTask != null) {
            cleanupTask.cancel();
            cleanupTask = null;
        }
        if (notifyServer != null) {
            notifyServer.stop();
        }
        logger.info("SecureAuthVelocity disabled.");
    }

    public ProxyServer getServer() {
        return server;
    }

    public Logger getLogger() {
        return logger;
    }

    public PluginConfig getPluginConfig() {
        return pluginConfig;
    }

    public AuthSessionStore getSessionStore() {
        return sessionStore;
    }
}
