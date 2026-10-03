package dev.tienday.secureauth;

import dev.tienday.secureauth.command.*;
import dev.tienday.secureauth.database.DatabaseManager;
import dev.tienday.secureauth.listener.*;
import dev.tienday.secureauth.security.LicenseManager;
import dev.tienday.secureauth.security.RateLimiter;
import dev.tienday.secureauth.security.TwoFactorManager;
import dev.tienday.secureauth.util.*;
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
    private LicenseManager licenseManager;
    private PluginHttpServer pluginHttpServer;

    private IpSessionStore ipSessionStore;
    private WebhookNotifier webhookNotifier;
    private BackupManager backupManager;

    @Override
    public void onEnable() {
        instance = this;

        // ── 1. Config ───────────────────────────────────────────────────────
        try {
            saveDefaultConfig();
            configManager = new ConfigManager(this);
            configManager.validate();
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "[Startup] Config lỗi, plugin disabled.", e);
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        // ── 2. License ──────────────────────────────────────────────────────
        try {
            licenseManager = new LicenseManager(this);
            if (!licenseManager.verify()) {
                getLogger().severe("[License] Invalid or expired license. Plugin disabled.");
                getServer().getPluginManager().disablePlugin(this);
                return;
            }
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "[License] Lỗi verify license, plugin disabled.", e);
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        // ── 3. Audit Logger ─────────────────────────────────────────────────
        try {
            auditLogger = new AuditLogger(this);
            auditLogger.start();
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "[Audit] Không khởi động được audit logger.", e);
        }

        // ── 4. Database ─────────────────────────────────────────────────────
        try {
            databaseManager = new DatabaseManager(this);
            databaseManager.init();
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "[DB] Kết nối database thất bại, plugin disabled.", e);
            if (auditLogger != null) auditLogger.logSystem("STARTUP_FAIL", "DB connection failed: " + e.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        // ── 5. Managers ─────────────────────────────────────────────────────
        sessionManager   = new SessionManager(this);
        rateLimiter      = new RateLimiter(this);
        twoFactorManager = new TwoFactorManager(this);

        try {
            ipSessionStore = new IpSessionStore(this);
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "[IpSessionStore] Không khởi tạo được.", e);
        }

        try {
            webhookNotifier = new WebhookNotifier(this);
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "[WebhookNotifier] Không khởi tạo được.", e);
        }

        try {
            backupManager = new BackupManager(this);
            backupManager.startScheduled();
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "[BackupManager] Không khởi tạo được.", e);
        }

        // ── 6. Commands ─────────────────────────────────────────────────────
        boolean commandsOk = true;
        commandsOk &= registerCommand("login",          new LoginCommand(this));
        commandsOk &= registerCommand("register",       new RegisterCommand(this));
        commandsOk &= registerCommand("link",           new LinkCommand(this));
        commandsOk &= registerCommand("authadmin",      new AuthAdminCommand(this));
        commandsOk &= registerCommand("authsetspawn",   new SetSpawnCommand(this));
        commandsOk &= registerCommand("uuid",           new UUIDCommand(this));
        commandsOk &= registerCommand("changepassword", new ChangePasswordCommand(this));

        if (!commandsOk) {
            getLogger().severe("[Commands] Một hoặc nhiều command thiếu trong plugin.yml — plugin disabled.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        // ── 7. Listeners ────────────────────────────────────────────────────
        getServer().getPluginManager().registerEvents(new AuthListener(this), this);
        getServer().getPluginManager().registerEvents(new OPGuardListener(this), this);
        getServer().getPluginManager().registerEvents(new DangerousCommandListener(this), this);
        getServer().getPluginManager().registerEvents(new CommandBlocker(this), this);

        // ── 8. Background tasks ─────────────────────────────────────────────
        try {
            sessionManager.startTimeoutTask();
            rateLimiter.startCleanupTask();
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "[Tasks] Không start được background task.", e);
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        // ── 9. HTTP server ──────────────────────────────────────────────────
        try {
            pluginHttpServer = new PluginHttpServer(this);
            pluginHttpServer.start();
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "[HTTP] Không start được HTTP server, plugin disabled.", e);
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        if (auditLogger != null) {
            auditLogger.logSystem("STARTUP", "SecureAuth enabled — version " + getDescription().getVersion());
        }
        getLogger().info("SecureAuth enabled successfully.");
    }

    private boolean registerCommand(String name, CommandExecutor executor) {
        PluginCommand cmd = getCommand(name);
        if (cmd == null) {
            getLogger().severe("[Commands] Command '" + name + "' missing from plugin.yml");
            return false;
        }
        cmd.setExecutor(executor);
        return true;
    }

    @Override
    public void onDisable() {
        if (pluginHttpServer != null) {
            try { pluginHttpServer.stop(); } catch (Exception e) { getLogger().warning("HTTP stop error: " + e.getMessage()); }
        }
        if (backupManager != null) {
            try { backupManager.shutdown(); } catch (Exception e) { getLogger().warning("BackupManager stop error: " + e.getMessage()); }
        }
        if (ipSessionStore != null) {
            try { ipSessionStore.shutdown(); } catch (Exception e) { getLogger().warning("IpSessionStore stop error: " + e.getMessage()); }
        }
        if (rateLimiter != null) {
            try { rateLimiter.shutdown(); } catch (Exception e) { getLogger().warning("RateLimiter stop error: " + e.getMessage()); }
        }
        if (sessionManager != null) {
            try { sessionManager.shutdown(); } catch (Exception e) { getLogger().warning("SessionManager stop error: " + e.getMessage()); }
        }
        if (databaseManager != null) {
            try { databaseManager.close(); } catch (Exception e) { getLogger().warning("DB close error: " + e.getMessage()); }
        }
        if (auditLogger != null) {
            try {
                auditLogger.logSystem("SHUTDOWN", "SecureAuth disabled");
                auditLogger.stop();
            } catch (Exception e) { getLogger().warning("AuditLogger stop error: " + e.getMessage()); }
        }
        instance = null;
        getLogger().info("SecureAuth disabled.");
    }

    // ── Getters ─────────────────────────────────────────────────────────────

    public static SecureAuthPlugin getInstance()  { return instance; }
    public ConfigManager getConfigManager()       { return configManager; }
    public DatabaseManager getDatabaseManager()   { return databaseManager; }
    public SessionManager getSessionManager()     { return sessionManager; }
    public RateLimiter getRateLimiter()           { return rateLimiter; }
    public TwoFactorManager getTwoFactorManager() { return twoFactorManager; }
    public AuditLogger getAuditLogger()           { return auditLogger; }
    public LicenseManager getLicenseManager()     { return licenseManager; }
    public IpSessionStore getIpSessionStore()     { return ipSessionStore; }
    public WebhookNotifier getWebhookNotifier()   { return webhookNotifier; }
    public BackupManager getBackupManager()       { return backupManager; }
}
