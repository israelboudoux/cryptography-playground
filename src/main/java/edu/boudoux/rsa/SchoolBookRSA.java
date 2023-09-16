package edu.boudoux.rsa;

import edu.boudoux.util.CryptographyUtils;
import org.apache.commons.codec.digest.DigestUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.util.function.Predicate;
import static edu.boudoux.util.CryptographyUtils.*;

public class SchoolBookRSA {

    public record PubKey (BigInteger e, BigInteger n) {}
    public record PrivKey (BigInteger d, BigInteger n) {}

    private static final Random RANDOMIZER = new SecureRandom();

    private static final BigInteger PADDING = new BigInteger("10000000", 2);

    /**
     * This is the default 'e' selected, but it could be any prime number that satisfies
     * gcd(e, p-1) = 1 and gcd(e, q-1) = 1.
     */
    public static final BigInteger DEFAULT_E = new BigInteger("17");

    public static BigInteger generatePrime(int totalBits, BigInteger e, BigInteger otherThan) {
        /*
           In order to generate a number lower than the total bits, one is subtracted from the total, since it will
           be multiplied later by another generated prime adopting the same strategy. This will guarantee that the
           multiplication of the operands will not earn a value greater than the total bits.
         */
        totalBits /= 2;

        // b001...0 (totalBits len)
        BigInteger totalBitsSet = new BigInteger(String.format("00%s0", "1".repeat(totalBits - 3)), 2);

        // b11...1
        BigInteger initialValue = new BigInteger(String.format("11%s1", "0".repeat(totalBits - 3)), 2);
        BigInteger genPrime;
        do {
            String shaResult = DigestUtils.sha512Hex(new Date().toString() + RANDOMIZER.nextLong()).repeat(1);
            String randomNumber = shaResult.substring(0, totalBits);

            genPrime = initialValue.xor(new BigInteger(randomNumber, 16).and(totalBitsSet));
        } while (!isPrime2(genPrime)
                    || !gcd(e, genPrime.subtract(BigInteger.ONE)).equals(BigInteger.ONE)
                    || genPrime.equals(otherThan));

        return genPrime;
    }

    /**
     * Allows one to generate the key components, namely the Public Key and Private Key, represented by a PubKey
     * and a PrivKey objects, respectively.
     *
     * @param keySize The key size to be used in the modulo.
     * @return a Map.Entry instance containing a PubKey instance in as the key and a PrivKey instance as the value.
     */
    public static Map.Entry<PubKey, PrivKey> generateKeyComponents(int keySize) {
        if (! validateKeySize(keySize)) {
            throw new IllegalArgumentException("Invalid key size!");
        }

        BigInteger e = generatePublicComponent();
        BigInteger p = generatePrime(keySize, e, null);
        BigInteger q = generatePrime(keySize, e, p);
        BigInteger n = p.multiply(q);
        BigInteger totient = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger d = generatePrivateComponent(e, totient);

        System.out.printf("[DEBUG] p: %s / q: %s%n", p, q);

        return Map.entry(new PubKey(e, n), new PrivKey(d, n));
    }

    private static boolean validateKeySize(int keySize) {
        return keySize >= 16 && keySize <= 1024 && keySize % 8 == 0;
    }

    private static boolean validatePlainText(String v, int keySize) {
        int maxPlainTextLength = (keySize - 8) / 8; // subtracting 8 bits reserved for padding
        return !v.isEmpty() && v.getBytes(StandardCharsets.UTF_8).length <= maxPlainTextLength;
    }

    private static BigInteger generatePublicComponent() {
        return DEFAULT_E;
    }

    private static BigInteger generatePrivateComponent(BigInteger e, BigInteger totientN) {
        return CryptographyUtils.mmi2(e, totientN);
    }

    public static BigInteger cipherPlainText(String plainTextInput, BigInteger e, BigInteger n) {
        BigInteger text = CryptographyUtils.toBigInteger(plainTextInput, PADDING);

        return CryptographyUtils.powerMod(text, e, n);
    }

    public static String decipher(BigInteger cypheredText, BigInteger privateKey, BigInteger n) {
        BigInteger plainTextRep = CryptographyUtils.powerMod(cypheredText, privateKey, n);
        return CryptographyUtils.toString(plainTextRep, PADDING, n);
    }

    public static void main(String[] args) {
        System.out.println("*** School book RSA ***");

        String totalBitsModuloInput = requestInput("Enter the Total Bits for the RSA modulo (min: 16/max: 1024): ", (String s) -> {
            try {
                int v = Integer.parseInt(s);
                return validateKeySize(v);
            } catch (NumberFormatException ignored) {}
            return false;
        });
        int totalBitsModulo = Integer.parseInt(totalBitsModuloInput);
        int maxPlainTextLength = (totalBitsModulo - 8) / 8;

        String plainTextInput = requestInput(String.format("Enter the plain text (max len: %d): ", maxPlainTextLength),
                (String s) -> validatePlainText(s, totalBitsModulo));

        Map.Entry<PubKey, PrivKey> keyComponents = generateKeyComponents(totalBitsModulo);
        BigInteger e = keyComponents.getKey().e();
        BigInteger n = keyComponents.getKey().n();
        BigInteger d = keyComponents.getValue().d();

        BigInteger cipheredTextRep = cipherPlainText(plainTextInput, e, n);
        String cipheredText = CryptographyUtils.toString(cipheredTextRep, null, n);

        BigInteger plainTextRep = CryptographyUtils.toBigInteger(plainTextInput, PADDING);
        System.out.printf("\nPlain text (int rep): %s\n\n", plainTextRep);
        System.out.printf("Public components [e: %s, n: %s]\n", e, n);
        System.out.printf("Private components [d: %s, n: %s]\n", d, n);
        System.out.printf("Ciphered text: %s (int rep: %s)\n\n", cipheredText, cipheredTextRep);

        System.out.println("Deciphering...");
        // we will assume 'n' is already supplied, and the cipher text as well
        String privateKey = requestInput("\nEnter the private key: ",
                (String s) -> !s.isEmpty() && n.compareTo(BigInteger.valueOf(s.length())) > 0);
        String plainText = decipher(cipheredTextRep, new BigInteger(privateKey), n);

        System.out.println("Plain text deciphered: " + plainText);
    }

    private static String requestInput(String message, Predicate<String> predicate) {
        Scanner scanner = new Scanner(System.in);

        String s;
        do {
            System.out.printf("%s", message);
            s = scanner.nextLine();

            if (! predicate.test(s)) {
                System.out.println("Invalid input!");
                continue;
            }
            break;
        } while (true);

        return s;
    }
}
