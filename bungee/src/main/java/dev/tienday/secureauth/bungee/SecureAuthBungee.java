package dev.tienday.secureauth.bungee;

import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.api.scheduler.ScheduledTask;

import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * BungeeCord / Waterfall companion for SecureAuth (Paper backend).
 * Receives HTTP notify from Paper after successful login; blocks server switch until then.
 */
public final class SecureAuthBungee extends Plugin {

    private PluginConfig pluginConfig;
    private AuthSessionStore sessionStore;
    private AuthNotifyServer notifyServer;
    private ScheduledTask cleanupTask;

    @Override
    public void onEnable() {
        pluginConfig = new PluginConfig(getDataFolder().toPath(), getLogger());
        sessionStore = new AuthSessionStore(pluginConfig.getSessionTimeoutMs());
        notifyServer = new AuthNotifyServer(this);

        getProxy().getPluginManager().registerListener(this, new AuthEventListener(this));
        notifyServer.start();

        if (pluginConfig.getSessionTimeoutMs() > 0) {
            cleanupTask = getProxy().getScheduler().schedule(this,
                    sessionStore::clearExpired, 5, 5, TimeUnit.MINUTES);
        }

        getLogger().info("SecureAuthBungee 1.0.3 enabled — notify "
                + pluginConfig.getHttpBind() + ":" + pluginConfig.getHttpPort());
    }

    @Override
    public void onDisable() {
        if (cleanupTask != null) {
            cleanupTask.cancel();
            cleanupTask = null;
        }
        if (notifyServer != null) {
            notifyServer.stop();
        }
        getLogger().info("SecureAuthBungee disabled.");
    }

    public PluginConfig getPluginConfig() {
        return pluginConfig;
    }

    public AuthSessionStore getSessionStore() {
        return sessionStore;
    }

    public Logger getPluginLogger() {
        return getLogger();
    }
}
