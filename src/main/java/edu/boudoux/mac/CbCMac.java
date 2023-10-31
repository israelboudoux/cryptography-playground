package edu.boudoux.mac;

import edu.boudoux.utils.CryptographyUtils;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.utils.AES;
import org.apache.commons.crypto.utils.Utils;
import org.apache.commons.lang3.tuple.Pair;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;

/**
 * The CBC-MAC uses AES-128 with 'Cipher Block Chaining' mode for generating the MAC for a message.
 */
public class CbCMac {

    /**
     * This class is used the break down the message into blocks of fixed size.
     */
    private static class MessageBlockBreaker {
        private final int blockSize;
        private final String message;
        private int currentOffset = 0;

        private MessageBlockBreaker (String message, int blockSize) {
            this.message = message;
            this.blockSize = blockSize;
        }

        public static MessageBlockBreaker of(String message, int blockSize) {
            return new MessageBlockBreaker(message, blockSize);
        }

        public String nextBlock() {
            if (currentOffset >= message.length()) {
                return null;
            }

            String currentBlock = message.substring(currentOffset, Math.min(currentOffset + blockSize, message.length()));
            currentOffset += blockSize;

            return currentBlock;
        }
    }

    public static String encrypt(String message, String secret) {
        final SecretKeySpec key = AES.newSecretKeySpec(secret.getBytes(StandardCharsets.UTF_8));
        final IvParameterSpec iv = new IvParameterSpec(secret.getBytes(StandardCharsets.UTF_8));

        final Properties properties = new Properties();
        properties.setProperty(CryptoCipherFactory.CLASSES_KEY, CryptoCipherFactory.CipherProvider.JCE.getClassName());

        final String transform = AES.CBC_PKCS5_PADDING;
        try (final CryptoCipher encipher = Utils.getCipherInstance(transform, properties)) {
            final byte[] input = message.getBytes(StandardCharsets.UTF_8);
            byte[] output = new byte[1024];

            encipher.init(Cipher.ENCRYPT_MODE, key, iv);
            int updateBytes = encipher.update(input, 0, input.length, output, 0);
            int finalBytes = encipher.doFinal(input, 0, 0, output, updateBytes);

            return new BigInteger(Arrays.copyOf(output, updateBytes + finalBytes)).toString(16);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Pair<String, BigInteger> encode(String message, String key) {
        BigInteger nonce = CryptographyUtils.generateNumber(BigInteger.ZERO, BigInteger.valueOf(Long.MAX_VALUE));
        String mac = _encode(message, key, nonce);

        return Pair.of(mac, nonce);
    }

    private static String _encode(String message, String key, BigInteger nonce) {
        if (message == null || message.isEmpty()) {
            throw new IllegalArgumentException("Message cannot be null/empty");
        }

        if (key == null || key.getBytes().length != 16) { // Using AES-128 requires a 16bytes key
            throw new IllegalArgumentException("Invalid key length. It must be 16 bytes long");
        }

        final MessageBlockBreaker messageBlockBreaker = MessageBlockBreaker.of(message, 16);
        String nextBlock, encryptionResult, messageBlockHex;
        BigInteger messageBlockBigIntRep, result = nonce;

        while ((nextBlock = messageBlockBreaker.nextBlock()) != null) {
            messageBlockBigIntRep = new BigInteger(nextBlock.getBytes());
            messageBlockBigIntRep = result.xor(messageBlockBigIntRep);
            messageBlockHex = messageBlockBigIntRep.toString(16);

            encryptionResult = encrypt(messageBlockHex.substring(0, Math.min(16, messageBlockHex.length())), key);
            result = new BigInteger(encryptionResult.substring(0, Math.min(32, encryptionResult.length())), 16);
        }

        return result.toString(16);
    }

    public static boolean verify(String message, String key, BigInteger nonce, String mac) {
        String generatedMac = _encode(message, key, nonce);

        return generatedMac.equals(mac);
    }
}
