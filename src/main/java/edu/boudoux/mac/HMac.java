package edu.boudoux.mac;

import org.apache.commons.codec.digest.DigestUtils;

import java.math.BigInteger;

public class HMac {

    private static final int TOTAL_BITS_HASH = 160; // SHA-1 = 160b

    private static final int TOTAL_BYTES_HASH = TOTAL_BITS_HASH / 8;

    /* inner padding - a padding value that has the same size as the hash function being used */
    private static final BigInteger IPAD = new BigInteger("36".repeat(TOTAL_BYTES_HASH), 16);

    /* outer padding - the same as inner padding */
    private static final BigInteger OPAD = new BigInteger("5c".repeat(TOTAL_BYTES_HASH), 16);

    public static String encode(String message, String key) {
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }

        if (key == null || key.isEmpty() || key.length() > TOTAL_BYTES_HASH) {
            throw new IllegalArgumentException(String.format("Invalid key (min len: 1 / max len: %d)", TOTAL_BYTES_HASH));
        }

        key = expand(key);
        final BigInteger keyBigIntRep = new BigInteger(key.getBytes());

        // key XOR IPAD
        BigInteger xoredKey = keyBigIntRep.xor(IPAD);

        String intermediaryHash = DigestUtils.sha1Hex(new String(xoredKey.toByteArray()) + message);

        // Key XOR OPAD
        xoredKey = keyBigIntRep.xor(OPAD);

        return DigestUtils.sha1Hex(new String(xoredKey.toByteArray()) + intermediaryHash);
    }

    /**
     * Expands the key by prefixing it with '0' until reach the length of the block size of the hash function.
     *
     * @param key
     * @return
     */
    private static String expand(String key) {
        return String.format("%s%s", "0".repeat(TOTAL_BYTES_HASH - key.length()), key);
    }

    public static boolean verify(String message, String key, String mac) {
        return encode(message, key).equals(mac);
    }
}
