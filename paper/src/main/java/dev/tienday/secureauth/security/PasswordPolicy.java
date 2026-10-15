package dev.tienday.secureauth.security;

import java.util.Locale;
import java.util.Set;

/**
 * Password strength checks — config-driven min length + optional mixed charset + entropy.
 */
public final class PasswordPolicy {

    private static final Set<String> COMMON = Set.of(
            "password", "password1", "password123", "123456", "12345678", "123456789",
            "qwerty", "qwerty123", "abc123", "letmein", "welcome", "admin", "admin123",
            "minecraft", "minecraft1", "iloveyou", "monkey", "dragon", "master", "login",
            "passw0rd", "changeme", "secret", "default"
    );

    private PasswordPolicy() {}

    public static boolean isCommon(String password) {
        if (password == null) return true;
        return COMMON.contains(password.toLowerCase(Locale.ROOT));
    }

    /**
     * @param minLen from config
     * @param requireMixed letter+digit (and prefer upper if mixed)
     * @param minEntropyBits 0 = skip entropy (default); 50 recommended when strict
     */
    public static boolean isStrong(String password, int minLen, boolean requireMixed, double minEntropyBits) {
        if (password == null) return false;
        if (password.length() < minLen || password.length() > 128) return false;
        if (isCommon(password)) return false;

        boolean lower = false, upper = false, digit = false, special = false;
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (Character.isLowerCase(c)) lower = true;
            else if (Character.isUpperCase(c)) upper = true;
            else if (Character.isDigit(c)) digit = true;
            else special = true;
        }

        if (requireMixed) {
            if (!digit) return false;
            if (!(lower || upper)) return false;
            // prefer both cases when length allows
            if (password.length() >= 12 && !(lower && upper)) {
                // soft: still accept letter+digit for shorter, but for 12+ require both cases
                return lower && upper;
            }
        }

        if (minEntropyBits > 0) {
            int pool = 0;
            if (lower) pool += 26;
            if (upper) pool += 26;
            if (digit) pool += 10;
            if (special) pool += 32;
            if (pool <= 1) return false;
            double entropy = password.length() * (Math.log(pool) / Math.log(2));
            if (entropy < minEntropyBits) return false;
        }
        return true;
    }
}
