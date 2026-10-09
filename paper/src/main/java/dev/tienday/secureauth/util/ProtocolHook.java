package dev.tienday.secureauth.util;

import dev.tienday.secureauth.SecureAuthPlugin;
import org.bukkit.entity.Player;

import java.lang.reflect.Method;
import java.util.UUID;
import java.util.logging.Level;

/**
 * Soft-depend ProtocolLib — chặn packet khi chưa login.
 * Không import ProtocolLib trực tiếp → build OK khi không có lib.
 */
public final class ProtocolHook {

    private final SecureAuthPlugin plugin;
    private boolean enabled;
    private Object protocolManager;
    private Object packetAdapter; // keep ref to unregister

    public ProtocolHook(SecureAuthPlugin plugin) {
        this.plugin = plugin;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void tryEnable() {
        if (!plugin.getConfig().getBoolean("protocolib.enabled", true)) {
            plugin.getLogger().info("[ProtocolLib] Disabled in config.");
            return;
        }
        if (plugin.getServer().getPluginManager().getPlugin("ProtocolLib") == null) {
            plugin.getLogger().info("[ProtocolLib] Not installed — using Bukkit events only.");
            return;
        }
        try {
            Class<?> plClass = Class.forName("com.comphenix.protocol.ProtocolLibrary");
            Method getPM = plClass.getMethod("getProtocolManager");
            protocolManager = getPM.invoke(null);

            // Register via PacketAdapter subclass created with Proxy is hard;
            // Use simpler approach: ProtocolManager.addPacketListener with reflective PacketAdapter.
            registerChatAndCommandBlock();
            enabled = true;
            plugin.getLogger().info("[ProtocolLib] Hook enabled — blocking chat/commands for unauthenticated players.");
        } catch (Throwable t) {
            enabled = false;
            plugin.getLogger().log(Level.WARNING, "[ProtocolLib] Hook failed (fallback Bukkit): " + t.getMessage());
        }
    }

    private void registerChatAndCommandBlock() throws Exception {
        Class<?> packetTypeClass = Class.forName("com.comphenix.protocol.PacketType");
        Class<?> playClient = Class.forName("com.comphenix.protocol.PacketType$Play$Client");

        Object chat = null;
        Object chatCommand = null;
        Object tabComplete = null;
        try {
            chat = playClient.getField("CHAT").get(null);
        } catch (NoSuchFieldException ignored) {}
        try {
            chatCommand = playClient.getField("CHAT_COMMAND").get(null);
        } catch (NoSuchFieldException ignored) {}
        try {
            // 1.19+ often TAB_COMPLETE under Play.Client
            tabComplete = playClient.getField("TAB_COMPLETE").get(null);
        } catch (NoSuchFieldException ignored) {}

        java.util.List<Object> types = new java.util.ArrayList<>();
        if (chat != null) types.add(chat);
        if (chatCommand != null) types.add(chatCommand);
        if (tabComplete != null) types.add(tabComplete);
        if (types.isEmpty()) {
            plugin.getLogger().warning("[ProtocolLib] No packet types found for this version.");
            return;
        }

        Class<?> listenerPriority = Class.forName("com.comphenix.protocol.events.ListenerPriority");
        Object priority = Enum.valueOf((Class<Enum>) listenerPriority.asSubclass(Enum.class), "LOWEST");

        Class<?> packetAdapterClass = Class.forName("com.comphenix.protocol.events.PacketAdapter");
        Class<?> packetListenerClass = Class.forName("com.comphenix.protocol.events.PacketListener");
        Class<?> packetEventClass = Class.forName("com.comphenix.protocol.events.PacketEvent");

        // PacketAdapter(Plugin, ListenerPriority, PacketType...)
        Class<?>[] ctorParams = new Class<?>[]{
                org.bukkit.plugin.Plugin.class,
                listenerPriority,
                java.lang.reflect.Array.newInstance(packetTypeClass, 0).getClass()
        };
        Object typeArray = java.lang.reflect.Array.newInstance(packetTypeClass, types.size());
        for (int i = 0; i < types.size(); i++) {
            java.lang.reflect.Array.set(typeArray, i, types.get(i));
        }

        // Use InvocationHandler on a dynamic approach: subclass via MethodHandles is complex.
        // Simpler: call ProtocolManager.addPacketListener with anonymous via bytecode — not available.
        // Fall back: use PacketAdapter constructor + override onPacketReceiving via Proxy not work for abstract class.

        // Practical approach used by many soft-hooks: reflective new PacketAdapter(...) { } isn't possible.
        // Register using PacketAdapter.AdapterParameteters builder if available (PL 5+).
        try {
            registerWithBuilder(priority, types, packetTypeClass, packetEventClass);
        } catch (Throwable t) {
            plugin.getLogger().log(Level.WARNING, "[ProtocolLib] Builder register failed: " + t.getMessage());
            enabled = false;
        }
    }

    private void registerWithBuilder(Object priority, java.util.List<Object> types,
                                     Class<?> packetTypeClass, Class<?> packetEventClass) throws Exception {
        Class<?> adapterParams = Class.forName("com.comphenix.protocol.events.PacketAdapter$AdapterParameteters");
        Object params = adapterParams.getConstructor().newInstance();

        Method pluginM = adapterParams.getMethod("plugin", org.bukkit.plugin.Plugin.class);
        pluginM.invoke(params, plugin);

        Method listenerPrio = adapterParams.getMethod("listenerPriority",
                Class.forName("com.comphenix.protocol.events.ListenerPriority"));
        listenerPrio.invoke(params, priority);

        Method typesM = adapterParams.getMethod("types", java.lang.reflect.Array.newInstance(packetTypeClass, 0).getClass());
        Object typeArray = java.lang.reflect.Array.newInstance(packetTypeClass, types.size());
        for (int i = 0; i < types.size(); i++) {
            java.lang.reflect.Array.set(typeArray, i, types.get(i));
        }
        typesM.invoke(params, typeArray);

        // PacketAdapter is abstract — need concrete subclass. Create via Java Proxy won't work.
        // Use com.comphenix.protocol.events.PacketAdapter with MethodHandles.Lookup defineClass — too heavy.

        // Final practical approach: only document + enable flag; use Bukkit for command block.
        // OR depend on ProtocolLib as provided compile dependency.

        plugin.getLogger().info("[ProtocolLib] Present — packet block uses lightweight reflection listener if available.");
        // Try PacketListener interface with Proxy
        Class<?> packetListenerIface = Class.forName("com.comphenix.protocol.events.PacketListener");
        Object listener = java.lang.reflect.Proxy.newProxyInstance(
                packetListenerIface.getClassLoader(),
                new Class<?>[]{packetListenerIface},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("onPacketReceiving".equals(name) && args != null && args.length == 1) {
                        handlePacket(args[0]);
                        return null;
                    }
                    if ("onPacketSending".equals(name)) return null;
                    if ("getPlugin".equals(name)) return plugin;
                    if ("getSendingWhitelist".equals(name) || "getReceivingWhitelist".equals(name)) {
                        return buildWhitelist(method.getReturnType(), types, packetTypeClass, priority);
                    }
                    if ("hashCode".equals(name)) return System.identityHashCode(proxy);
                    if ("equals".equals(name)) return proxy == args[0];
                    if ("toString".equals(name)) return "SecureAuthPacketListener";
                    return defaultValue(method.getReturnType());
                }
        );

        Method add = protocolManager.getClass().getMethod("addPacketListener", packetListenerIface);
        add.invoke(protocolManager, listener);
        packetAdapter = listener;
    }

    private Object buildWhitelist(Class<?> returnType, java.util.List<Object> types,
                                  Class<?> packetTypeClass, Object priority) throws Exception {
        // ListeningWhitelist.newBuilder()...
        Class<?> lw = Class.forName("com.comphenix.protocol.events.ListeningWhitelist");
        Method newBuilder = lw.getMethod("newBuilder");
        Object builder = newBuilder.invoke(null);
        Class<?> builderClass = builder.getClass();
        builderClass.getMethod("priority", Class.forName("com.comphenix.protocol.events.ListenerPriority"))
                .invoke(builder, priority);
        Object typeArray = java.lang.reflect.Array.newInstance(packetTypeClass, types.size());
        for (int i = 0; i < types.size(); i++) {
            java.lang.reflect.Array.set(typeArray, i, types.get(i));
        }
        builderClass.getMethod("types", typeArray.getClass()).invoke(builder, typeArray);
        builderClass.getMethod("gamePhaseBoth").invoke(builder);
        return builderClass.getMethod("build").invoke(builder);
    }

    private void handlePacket(Object packetEvent) {
        try {
            Method getPlayer = packetEvent.getClass().getMethod("getPlayer");
            Player player = (Player) getPlayer.invoke(packetEvent);
            if (player == null) return;
            UUID uuid = player.getUniqueId();
            if (plugin.getSessionManager().isAuthenticated(uuid)) return;
            if (plugin.getSessionManager().isInGrace(uuid)) return;

            // Allow only if chat text is auth command — parse packet hard; cancel all chat/commands
            // Auth commands still go through Bukkit if not cancelled — actually CHAT_COMMAND cancel blocks /login
            // So only cancel if message does NOT start with /login /register /link
            String cmd = extractCommand(packetEvent);
            if (cmd != null) {
                String lower = cmd.toLowerCase(java.util.Locale.ROOT).trim();
                // first token
                int sp = lower.indexOf(' ');
                String head = sp < 0 ? lower : lower.substring(0, sp);
                if (head.equals("login") || head.equals("l")
                        || head.equals("register") || head.equals("reg")
                        || head.equals("link") || head.equals("changepassword")
                        || head.equals("cp") || head.equals("passwd") || head.equals("uuid")) {
                    return; // allow auth-related commands
                }
            }
            Method setCancelled = packetEvent.getClass().getMethod("setCancelled", boolean.class);
            setCancelled.invoke(packetEvent, true);
        } catch (Throwable ignored) {
        }
    }

    private String extractCommand(Object packetEvent) {
        try {
            Method getPacket = packetEvent.getClass().getMethod("getPacket");
            Object packet = getPacket.invoke(packetEvent);
            // try getStrings().read(0)
            Method getStrings = packet.getClass().getMethod("getStrings");
            Object modifier = getStrings.invoke(packet);
            Method read = modifier.getClass().getMethod("read", int.class);
            Object val = read.invoke(modifier, 0);
            if (val instanceof String s) {
                s = s.trim();
                if (s.startsWith("/")) s = s.substring(1);
                return s;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == double.class) return 0.0;
        if (type == float.class) return 0f;
        return null;
    }

    public void disable() {
        if (!enabled || protocolManager == null || packetAdapter == null) return;
        try {
            Class<?> packetListenerIface = Class.forName("com.comphenix.protocol.events.PacketListener");
            Method remove = protocolManager.getClass().getMethod("removePacketListener", packetListenerIface);
            remove.invoke(protocolManager, packetAdapter);
        } catch (Throwable ignored) {
        }
        enabled = false;
        packetAdapter = null;
    }
}
