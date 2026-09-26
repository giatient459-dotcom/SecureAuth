package dev.tienday.secureauth;

import dev.tienday.secureauth.command.AuthAdminCommand;
import dev.tienday.secureauth.command.LinkCommand;
import dev.tienday.secureauth.command.LoginCommand;
import dev.tienday.secureauth.command.RegisterCommand;
import dev.tienday.secureauth.command.ChangePasswordCommand;
import dev.tienday.secureauth.command.SetSpawnCommand;
import dev.tienday.secureauth.command.UUIDCommand;
import dev.tienday.secureauth.database.DatabaseManager;
import dev.tienday.secureauth.listener.AuthListener;
import dev.tienday.secureauth.listener.CommandBlocker;
import dev.tienday.secureauth.listener.DangerousCommandListener;
import dev.tienday.secureauth.listener.OPGuardListener;
import dev.tienday.secureauth.security.RateLimiter;
import dev.tienday.secureauth.security.TwoFactorManager;
import dev.tienday.secureauth.util.AuditLogger;
import dev.tienday.secureauth.util.ConfigManager;
import dev.tienday.secureauth.util.PluginHttpServer;
import dev.tienday.secureauth.util.SessionManager;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.PluginCommand;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.logging.Level;

public final class SecureAuthPlugin extends JavaPlugin {

    private static SecureAuthPlugin instance;

    private ConfigManager configManager;
    private DatabaseManager databaseManager;
    private SessionManager sessionManager;
    private RateLimiter rateLimiter;
    private TwoFactorManager twoFactorManager;
    private AuditLogger auditLogger;
    private PluginHttpServer pluginHttpServer;

    @Override
    public void onEnable() {
        instance = this;

        saveDefaultConfig();
        configManager = new ConfigManager(this);
        configManager.validate();

        // AuditLogger starts before DB — logs even if DB fails
        auditLogger = new AuditLogger(this);
        auditLogger.start();

        databaseManager = new DatabaseManager(this);
        try {
            databaseManager.init();
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "Failed to connect to database! Disabling plugin.", e);
            auditLogger.logSystem("STARTUP_FAIL", "DB connection failed: " + e.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        sessionManager   = new SessionManager(this);
        rateLimiter      = new RateLimiter(this);
        twoFactorManager = new TwoFactorManager(this);

        registerCommand("login",        new LoginCommand(this));
        registerCommand("register",     new RegisterCommand(this));
        registerCommand("link",         new LinkCommand(this));
        registerCommand("authadmin",    new AuthAdminCommand(this));
        registerCommand("authsetspawn", new SetSpawnCommand(this));
        registerCommand("uuid",            new UUIDCommand(this));
        registerCommand("changepassword",   new ChangePasswordCommand(this));

        // Order: AuthListener first (blocks unauthed), then guards
        getServer().getPluginManager().registerEvents(new AuthListener(this), this);
        getServer().getPluginManager().registerEvents(new OPGuardListener(this), this);
        getServer().getPluginManager().registerEvents(new DangerousCommandListener(this), this);
        getServer().getPluginManager().registerEvents(new CommandBlocker(this), this);

        sessionManager.startTimeoutTask();
        rateLimiter.startCleanupTask();

        pluginHttpServer = new PluginHttpServer(this);
        pluginHttpServer.start();

        auditLogger.logSystem("STARTUP", "SecureAuth enabled — version " + getDescription().getVersion());
        getLogger().info("SecureAuth enabled successfully.");
    }

    private void registerCommand(String name, CommandExecutor executor) {
        PluginCommand cmd = getCommand(name);
        if (cmd == null) {
            getLogger().severe("Command '" + name + "' missing from plugin.yml — disabling plugin.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        cmd.setExecutor(executor);
    }

    @Override
    public void onDisable() {
        if (sessionManager  != null) sessionManager.shutdown();
        if (rateLimiter     != null) rateLimiter.shutdown();
        if (pluginHttpServer != null) pluginHttpServer.stop();
        if (databaseManager != null) databaseManager.close();
        if (auditLogger     != null) {
            auditLogger.logSystem("SHUTDOWN", "SecureAuth disabled");
            auditLogger.stop();
        }
        instance = null;
        getLogger().info("SecureAuth disabled.");
    }

    public static SecureAuthPlugin getInstance()      { return instance; }
    public ConfigManager getConfigManager()           { return configManager; }
    public DatabaseManager getDatabaseManager()       { return databaseManager; }
    public SessionManager getSessionManager()         { return sessionManager; }
    public RateLimiter getRateLimiter()               { return rateLimiter; }
    public TwoFactorManager getTwoFactorManager()     { return twoFactorManager; }
    public AuditLogger getAuditLogger()               { return auditLogger; }
}
