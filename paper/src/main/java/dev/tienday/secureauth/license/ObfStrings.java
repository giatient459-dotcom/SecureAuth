package dev.tienday.secureauth.license;

/**
 * Chuỗi nhạy cảm được XOR obfuscate — không để plaintext trong bytecode dễ đọc.
 * XOR key cố định; đổi secret → chạy lại tool encode bên dưới (comment).
 */
public final class ObfStrings {

    private static final int XOR_KEY = 0x5A;

    // SecureAuth_Lic_2026_TienDay_HMAC_v1  XOR 0x5A
    private static final byte[] HMAC_SECRET_OBF = {
            9, 63, 57, 47, 40, 63, 27, 47, 46, 50, 5, 22, 51, 57, 5,
            104, 106, 104, 108, 5, 14, 51, 63, 52, 30, 59, 35, 5,
            18, 23, 27, 25, 5, 44, 107
    };

    private ObfStrings() {}

    /** Secret dùng cho HMAC license — giải mã runtime. */
    public static String hmacSecret() {
        return xorDecode(HMAC_SECRET_OBF);
    }

    public static String xorDecode(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ XOR_KEY);
        }
        return new String(out, java.nio.charset.StandardCharsets.UTF_8);
    }

    /** Dùng khi đổi secret (chạy snippet trong IDE). */
    public static byte[] xorEncode(String plain) {
        byte[] in = plain.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ XOR_KEY);
        }
        return out;
    }
}
