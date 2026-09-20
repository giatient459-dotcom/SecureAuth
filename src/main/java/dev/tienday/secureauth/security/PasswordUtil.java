package dev.tienday.secureauth.security;

import dev.tienday.secureauth.SecureAuthPlugin;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Argon2id hashing in PHC string format:
 *   $argon2id$v=19$m=<memKb>,t=<iters>,p=<par>$<b64salt>$<b64hash>
 *
 * Disabled accounts use the marker "!disabled"; verify() always returns false.
 */
public final class PasswordUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;
    private static final String DISABLED_MARKER = "!disabled";

    // Bounds to protect against maliciously crafted hashes.
    private static final int MAX_MEMORY_KB   = 4 * 1024 * 1024;
    private static final int MAX_ITERATIONS  = 100;
    private static final int MAX_PARALLELISM = 64;
    private static final int MAX_SALT_BYTES  = 64;
    private static final int MAX_HASH_BYTES  = 1024;

    private PasswordUtil() {}

    public static String hash(String password) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("password must not be empty");
        }
        SecureAuthPlugin plugin = SecureAuthPlugin.getInstance();
        int iterations  = plugin.getConfigManager().getArgon2Iterations();
        int memoryKb    = plugin.getConfigManager().getArgon2MemoryKb();
        int parallelism = plugin.getConfigManager().getArgon2Parallelism();

        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);

        byte[] hash = argon2id(password.toCharArray(), salt, iterations, memoryKb, parallelism, HASH_LENGTH);

        return String.format("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
                memoryKb, iterations, parallelism,
                Base64.getEncoder().withoutPadding().encodeToString(salt),
                Base64.getEncoder().withoutPadding().encodeToString(hash));
    }

    public static boolean verify(String password, String phcHash) {
        if (password == null || phcHash == null || phcHash.isEmpty()) return false;
        if (isDisabled(phcHash)) return false;

        try {
            String[] parts = phcHash.split("\\$");
            if (parts.length != 6) return false;
            if (!"argon2id".equals(parts[1])) return false;
            if (!"v=19".equals(parts[2])) return false;

            String[] params = parts[3].split(",");
            if (params.length != 3) return false;

            int memoryKb    = Integer.parseInt(params[0].split("=")[1]);
            int iterations  = Integer.parseInt(params[1].split("=")[1]);
            int parallelism = Integer.parseInt(params[2].split("=")[1]);

            if (memoryKb    <= 0 || memoryKb    > MAX_MEMORY_KB)   return false;
            if (iterations  <= 0 || iterations  > MAX_ITERATIONS)  return false;
            if (parallelism <= 0 || parallelism > MAX_PARALLELISM) return false;

            byte[] salt         = decodeB64NoPad(parts[4]);
            byte[] expectedHash = decodeB64NoPad(parts[5]);
            if (salt == null || expectedHash == null) return false;
            if (salt.length == 0 || salt.length > MAX_SALT_BYTES) return false;
            if (expectedHash.length == 0 || expectedHash.length > MAX_HASH_BYTES) return false;

            byte[] actualHash = argon2id(password.toCharArray(), salt,
                    iterations, memoryKb, parallelism, expectedHash.length);

            return constantTimeEquals(actualHash, expectedHash);
        } catch (Exception e) {
            return false;
        }
    }

    public static String disabledHash() {
        return DISABLED_MARKER;
    }

    public static boolean isDisabled(String phcHash) {
        return phcHash == null || phcHash.isEmpty() || DISABLED_MARKER.equals(phcHash);
    }

    // ---- internals ----

    private static byte[] argon2id(char[] password, byte[] salt,
                                   int iterations, int memoryKb, int parallelism, int outLen) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withIterations(iterations)
                .withMemoryAsKB(memoryKb)
                .withParallelism(parallelism)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);

        byte[] result = new byte[outLen];
        generator.generateBytes(password, result, 0, outLen);
        return result;
    }

    private static byte[] decodeB64NoPad(String s) {
        if (s == null) return null;
        int pad = (4 - (s.length() % 4)) % 4;
        try {
            return Base64.getDecoder().decode(s + "=".repeat(pad));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
        return diff == 0;
    }
}