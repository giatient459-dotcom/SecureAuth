package dev.tienday.secureauth;

import dev.tienday.secureauth.command.AuthAdminCommand;
import dev.tienday.secureauth.command.LinkCommand;
import dev.tienday.secureauth.command.LoginCommand;
import dev.tienday.secureauth.command.RegisterCommand;
import dev.tienday.secureauth.database.DatabaseManager;
import dev.tienday.secureauth.listener.AuthListener;
import dev.tienday.secureauth.listener.CommandBlocker;
import dev.tienday.secureauth.listener.DangerousCommandListener;
import dev.tienday.secureauth.listener.OPGuardListener;
import dev.tienday.secureauth.security.RateLimiter;
import dev.tienday.secureauth.security.TwoFactorManager;
import dev.tienday.secureauth.util.AuditLogger;
import dev.tienday.secureauth.util.ConfigManager;
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
    /** FIX #1: lưu reference để có thể gọi reload() khi config đổi. */
    private CommandBlocker commandBlocker;

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

        // FIX #3: kiểm tra kết quả registerCommand — nếu fail thì dừng onEnable.
        if (!registerCommand("login",     new LoginCommand(this)))    return;
        if (!registerCommand("register",  new RegisterCommand(this))) return;
        if (!registerCommand("link",      new LinkCommand(this)))     return;
        if (!registerCommand("authadmin", new AuthAdminCommand(this))) return;

        // Order: AuthListener first (blocks unauthed), then guards
        getServer().getPluginManager().registerEvents(new AuthListener(this), this);
        getServer().getPluginManager().registerEvents(new OPGuardListener(this), this);
        getServer().getPluginManager().registerEvents(new DangerousCommandListener(this), this);

        // FIX #1: tạo CommandBlocker, lưu reference, rồi mới register.
        commandBlocker = new CommandBlocker(this);
        getServer().getPluginManager().registerEvents(commandBlocker, this);

        sessionManager.startTimeoutTask();
        rateLimiter.startCleanupTask();

        auditLogger.logSystem("STARTUP", "SecureAuth enabled — version " + getDescription().getVersion());
        getLogger().info("SecureAuth enabled successfully.");
    }

    /**
     * FIX #3: trả về boolean thay vì void, để onEnable() biết khi nào cần dừng.
     * Trước đây disablePlugin() được gọi nhưng onEnable() vẫn chạy tiếp → state
     * không nhất quán, log rác.
     */
    private boolean registerCommand(String name, CommandExecutor executor) {
        PluginCommand cmd = getCommand(name);
        if (cmd == null) {
            getLogger().severe("Command '" + name + "' missing from plugin.yml — disabling plugin.");
            getServer().getPluginManager().disablePlugin(this);
            return false;
        }
        cmd.setExecutor(executor);
        return true;
    }

    /**
     * FIX #2: reload toàn bộ config và các manager có cache.
     * Gọi từ AuthAdminCommand khi admin chạy /authadmin reload.
     */
    public void reload() {
        reloadConfig();
        configManager.validate();
        if (commandBlocker != null) {
            commandBlocker.reload();
        }
        getLogger().info("[SecureAuth] Configuration reloaded.");
        auditLogger.logSystem("RELOAD", "Configuration reloaded by admin");
    }

    @Override
    public void onDisable() {
        if (sessionManager  != null) { sessionManager.shutdown();  sessionManager = null; }
        if (rateLimiter     != null) { rateLimiter.shutdown();     rateLimiter = null; }
        if (databaseManager != null) { databaseManager.close();    databaseManager = null; }
        if (auditLogger     != null) {
            auditLogger.logSystem("SHUTDOWN", "SecureAuth disabled");
            auditLogger.stop();
            auditLogger = null;
        }
        // FIX #4: set null hết các manager để tránh giữ reference khi plugin unload.
        twoFactorManager = null;
        configManager    = null;
        commandBlocker   = null;
        instance         = null;
        getLogger().info("SecureAuth disabled.");
    }

    public static SecureAuthPlugin getInstance()      { return instance; }
    public ConfigManager getConfigManager()           { return configManager; }
    public DatabaseManager getDatabaseManager()       { return databaseManager; }
    public SessionManager getSessionManager()         { return sessionManager; }
    public RateLimiter getRateLimiter()               { return rateLimiter; }
    public TwoFactorManager getTwoFactorManager()     { return twoFactorManager; }
    public AuditLogger getAuditLogger()               { return auditLogger; }
    /** FIX #1: getter cho CommandBlocker. */
    public CommandBlocker getCommandBlocker()         { return commandBlocker; }
}
