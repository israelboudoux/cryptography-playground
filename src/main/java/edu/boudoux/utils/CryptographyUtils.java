package edu.boudoux.utils;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.utils.AES;
import org.apache.commons.crypto.utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

public final class CryptographyUtils {

    private static final Random RANDOMIZER = new SecureRandom();

    /**
     * Implements Greatest Common Divisor using Euclid's Algorithm. Both operands must be positive.
     */
    public static long gcd(long a,long b) {
        if (b == 0) return a;

        return gcd(b,a % b);
    }

    public static BigInteger gcd(BigInteger a,BigInteger b) {
        if (b.equals(BigInteger.ZERO)) return a;

        return gcd(b,a.remainder(b));
    }

    /**
     * Calculates the Modular Multiplicative Inverse (MMI) between the two given numbers. It does the calculation
     * in an inefficient way using brute force.
     *
     * @param a
     * @param b
     * @return -1 if there isn't a MMI,otherwise,returns the calculated MMI
     */
    public static long mmi1(long a,long b) {
        if (b == 1) return -1;

        long gcd = gcd(a,b);

        if (gcd != 1) return -1;

        long mmi = 1;
        while(a * mmi % b != 1) {
            mmi++;
        }

        return mmi;
    }

    /**
     * Tests if the first param is greater than the second one.
     *
     * @param a
     * @param b
     * @return
     */
    public static boolean greaterThan(BigInteger a, BigInteger b) {
        return a.compareTo(b) > 0;
    }

    /**
     * Tests if the first param is lower than or equal to the second one.
     *
     * @param a
     * @param b
     * @return
     */
    public static boolean lowerThanOrEqual(BigInteger a, BigInteger b) {
        return a.compareTo(b) <= 0;
    }

    /**
     * Tests if the first param is greater than or equal to the second one.
     *
     * @param a
     * @param b
     * @return
     */
    public static boolean greaterThanOrEqual(BigInteger a, BigInteger b) {
        return a.compareTo(b) >= 0;
    }

    /**
     * Tests if the first param is lower than the second one.
     *
     * @param a
     * @param b
     * @return
     */
    public static boolean lowerThan(BigInteger a, BigInteger b) {
        return a.compareTo(b) < 0;
    }

    public static BigInteger min(BigInteger a, BigInteger b) {
        return a.compareTo(b) < 0 ? a : b;
    }

    public static BigInteger max(BigInteger a, BigInteger b) {
        return a.compareTo(b) > 0 ? a : b;
    }

    public static BigInteger mmi2(BigInteger a, BigInteger b) {
        assert greaterThan(b, BigInteger.ZERO);

        BigInteger r = a.remainder(b);
        BigInteger x = BigInteger.ONE, y = r.subtract(a).divide(b);
        BigInteger a_1 = b,b_1 = r;

        if (r.equals(BigInteger.ZERO)) return BigInteger.valueOf(-1);

        BigInteger x_1 = BigInteger.ZERO;
        BigInteger y_1 = BigInteger.ZERO, y_2;

        int i = 1;
        BigInteger minusOne = BigInteger.valueOf(-1);
        while(!b_1.equals(BigInteger.ZERO) && !b_1.equals(BigInteger.ONE)) {
            r = a_1.remainder(b_1);
            y_2 = a_1.multiply(minusOne).add(r).divide(b_1);

            if (i++ % 2 == 0) {
                x = y_2.multiply(x_1).add(x);
                y = y_2.multiply(y_1).add(y);
            } else {
                x_1 = y_2.multiply(x).add(x_1);
                y_1 = y_2.multiply(y).add(y_1);
            }

            a_1 = b_1;
            b_1 = r;
        }

        if (!b_1.equals(BigInteger.ONE)) return minusOne;

        BigInteger result = (i - 1) % 2 == 0 ? x : x_1;

        if (lowerThan(result, BigInteger.ZERO)) {
            return result.add(b);
        }

        return result;
    }

    /**
     * This method calculates the power mod of a number using an efficient algorithm. It can be used to calculate the
     * power mod of very big numbers efficiently.
     *
     * @param base
     * @param power
     * @param mod
     * @return
     */
    public static BigInteger powerMod(BigInteger base, BigInteger power, BigInteger mod) {
        BigInteger result = new BigInteger("1");
        long originalPower = power.longValue();

        while (greaterThan(power, BigInteger.ZERO)) {
            if (power.and(BigInteger.ONE).equals(BigInteger.ONE)) {
                result = result.multiply(base).remainder(mod);
            }
            power = power.shiftRight(1);
            base = base.multiply(base).remainder(mod);
        }

        return result;
    }

    /**
     * Uses Miller-Rabin Probabilistic Algorithm to verify if a given number is prime. As a probabilistic method for primality
     * testing, once a number is found to be prime, the resulting probability is about (1 - 1/4^T), where T is the total number
     * of probes.
     *
     * @return
     */
    public static boolean isPrime(BigInteger p) {
        if (p.equals(BigInteger.TWO)) {
            return true;
        } else if ((p.and(BigInteger.ONE)).equals(BigInteger.ZERO)) { // are you an even number?
            return false;
        }

        BigInteger pMinusOne = p.subtract(BigInteger.ONE);

        // 1 < probe < (p - 1)
        Random random = new Random(pMinusOne.longValue());

        int q = oddMultiplier(pMinusOne);
        BigInteger k = pMinusOne.divide(BigInteger.TWO.pow(q));

        int isPrime = 0x0;
        int maxProbes = 5;
        long bound = lowerThanOrEqual(p, BigInteger.valueOf(Long.MAX_VALUE)) ? p.longValue() : 7920;
        long[] probeList = random.longs(maxProbes,2, bound).toArray();
        BigInteger calc, bdProbe, _2power;

        for(long probe: probeList) {
            bdProbe = BigInteger.valueOf(probe);
            _2power = BigInteger.ONE;
            for (int i = 0; i <= q; i++) {
                calc = powerMod(bdProbe, _2power.multiply(k), p);
                if (calc.longValue() == 1 || calc.equals(pMinusOne)) {
                    isPrime = isPrime << 1 | 0x1;
                    break;
                }

                _2power = _2power.multiply(BigInteger.TWO);
            }

            if (isPrime == 0x0) {
                break;
            }
        }

        return isPrime == 0x1f; // 0x1f == b11111 - this value matches with the maxProbes (one bit for each probe)
    }

    /**
     * All even numbers can be written as a potency of 2 times an odd number. This method return the odd multiplier.
     *
     * @param value
     * @return
     */
    private static int oddMultiplier(BigInteger value) {
        if (lowerThanOrEqual(value, BigInteger.ZERO)) {
            return 0;
        }

        int result = 0;

        while (value.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
            result++;
            value = value.shiftRight(1);
        }

        return result;
    }

    public static BigInteger toBigInteger(String plainTextInput) {
        byte[] content = plainTextInput.getBytes(StandardCharsets.UTF_8);
        BigInteger text = BigInteger.ZERO;
        for(int i = content.length - 1; i >= 0; i--) {
            byte b = content[i];
            text = text.shiftLeft(8).add(new BigInteger(String.valueOf(b & 0xff)));
        }

        return text;
    }

    /**
     * @param value
     * @param modulo
     * @return
     */
    public static String toString(BigInteger value, BigInteger modulo) {
        BigInteger mask = new BigInteger("ff", 16);
        byte[] content = new byte[modulo.bitLength() / 8];
        int lastContentIndex = 0, i = 0;

        do {
            lastContentIndex++;
            content[i++] = value.and(mask).byteValue();
            value = value.shiftRight(8);
        } while(!value.equals(BigInteger.ZERO));

        return new String(content, 0, lastContentIndex, StandardCharsets.UTF_8);
    }

    /**
     * Generates a prime having the total bits specified.
     *
     * @param totalBits
     * @return
     */
    public static BigInteger generatePrime(int totalBits) {
        if (totalBits < 8 || totalBits % 8 != 0) {
            throw new IllegalArgumentException("totalBits is invalid");
        }

        // This enforces the full bits specified will be used - this number is an odd one
        final BigInteger minBitsSet = new BigInteger(String.format("1%s1", "0".repeat(totalBits - 2)), 2);

        BigInteger result;
        do {
            // sha1 = 160bits
            String sha1Result = DigestUtils.sha1Hex(RANDOMIZER.nextLong() + "").repeat(1 + totalBits / 160);

            // Picks only the totalBits MSB
            final BigInteger generatedNumber = new BigInteger(sha1Result, 16).shiftRight(sha1Result.length() * 4 - totalBits);

            result = minBitsSet.or(generatedNumber);
            while (!isPrime(result)) {
                result = result.add(BigInteger.TWO);
            }
        } while (result.bitLength() > totalBits); // prevents from generating higher values than the required

        return result;
    }

    /**
     * Generates a number in the range specified. The bound is non-inclusive.
     *
     * @param origin
     * @param bound
     * @return
     */
    public static BigInteger generateNumber(BigInteger origin, BigInteger bound) {
        if (origin == null || bound == null || lowerThan(origin, BigInteger.ZERO)
                || lowerThan(bound, origin)) {
            throw new IllegalArgumentException("Invalid parameters");
        }

        String sha1Digest;
        long r;
        BigInteger result = BigInteger.ZERO;

        for (int c = 1; c <= 10; c++) {
            r = RANDOMIZER.nextLong();
            sha1Digest = DigestUtils.sha1Hex(r + "" + c);
            result = result.add(new BigInteger(sha1Digest, 16)).mod(bound);

            if (lowerThan(result, origin)) {
                result = origin;
            }
        }

        return result;
    }

    /**
     * This method only tests the generator for at maximum 1M elements in the group. So it is likely that the number returned
     * isn't a generator for the cyclic group, but to a cyclic subgroup.
     *
     * @param p
     * @return
     */
    public static BigInteger getGenerator(BigInteger p) {
        if (p == null || p.equals(BigInteger.TWO) || ! isPrime(p)) {
            throw new IllegalArgumentException("Invalid param");
        }

        final int MAX_ELEMENTS_TO_TEST = min(p.subtract(BigInteger.ONE), BigInteger.valueOf(1_000_000)).intValue();
        Map<BigInteger, String> bigIntegerStringMap = new HashMap<>(MAX_ELEMENTS_TO_TEST);
        BigInteger generator = BigInteger.TWO;
        boolean possibleGeneratorFound = false;

        OUTER_LOOP:
        while (! possibleGeneratorFound) {
            bigIntegerStringMap.clear();

            for (int i = 0; i < MAX_ELEMENTS_TO_TEST; i++) {
                BigInteger element = powerMod(generator, BigInteger.valueOf(i), p);

                if (bigIntegerStringMap.containsKey(element)) {
                    generator = generator.add(BigInteger.ONE);
                    continue OUTER_LOOP;
                }

                bigIntegerStringMap.put(element, "");
            }

            possibleGeneratorFound = true;
        }

        return generator;
    }

    /**
     * Performs the encryption of the message using AES.
     *
     * @param message
     * @param secret
     * @return
     */
    public static String aesEncryption(String message, String secret) {
        secret = secret.substring(0, Math.min(16, secret.length()));

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

    /**
     * Performs the decryption of the message using AES.
     *
     * @param cipherText
     * @param secret
     * @return
     */
    public static String aesDecryption(String cipherText, String secret) {
        secret = secret.substring(0, Math.min(16, secret.length()));

        final SecretKeySpec key = AES.newSecretKeySpec(secret.getBytes(StandardCharsets.UTF_8));
        final IvParameterSpec iv = new IvParameterSpec(secret.getBytes(StandardCharsets.UTF_8));

        final Properties properties = new Properties();
        properties.setProperty(CryptoCipherFactory.CLASSES_KEY, CryptoCipherFactory.CipherProvider.JCE.getClassName());
        final String transform = AES.CBC_PKCS5_PADDING;
        try (final CryptoCipher decipher = Utils.getCipherInstance(transform, properties)) {
            decipher.init(Cipher.DECRYPT_MODE, key, iv);
            final byte[] decoded = new byte[1024];
            byte[] messageBytes = new BigInteger(cipherText, 16).toByteArray();

            decipher.doFinal(messageBytes, 0, messageBytes.length, decoded, 0);

            return new String(Arrays.copyOf(decoded, messageBytes.length), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
