package edu.boudoux;

import edu.boudoux.util.CryptographyUtils;
import org.apache.commons.codec.digest.DigestUtils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Random;
import java.util.Scanner;
import java.util.function.Predicate;
import static edu.boudoux.util.CryptographyUtils.*;

public class SchoolBookRSA {

    private static final Random RANDOMIZER = new SecureRandom();

    private static final BigInteger PADDING = new BigInteger("00111111", 2);

    /**
     * This is the default 'e' selected, but it could be any prime number that satisfies
     * gcd(e, p-1) = 1 and gcd(e, q-1) = 1.
     */
    private static final BigInteger DEFAULT_E = new BigInteger("17");

    public static BigInteger generatePrime(int totalBits, BigInteger e) {
        /*
           In order to generate a number lower than the total bits, one is subtracted from the total, since it will
           be multiplied later by another generated prime adopting the same strategy. This will guarantee that the
           multiplication of the operands will not earn a value greater than the total bits.
         */
        totalBits--;

        // b001...0 (totalBits len)
        BigInteger totalBitsSet = new BigInteger(String.format("00%s0", "1".repeat(totalBits - 3)), 2);

        // b11...1
        BigInteger initialValue = new BigInteger(String.format("11%s1", "0".repeat(totalBits - 3)), 2);
        BigInteger genPrime;
        do {
            String shaResult = DigestUtils.sha512Hex(new Date().toString() + RANDOMIZER.nextLong()).repeat(1);
            String randomNumber = shaResult.substring(0, totalBits);

            genPrime = initialValue.xor(new BigInteger(randomNumber, 16).and(totalBitsSet));
        } while (! isPrime2(genPrime) && !gcd(e, genPrime.subtract(BigInteger.ONE)).equals(BigInteger.ONE));

        return genPrime;
    }

    public static BigInteger generatePrivateComponent(BigInteger e, BigInteger totientN) {
        return CryptographyUtils.mmi2(e, totientN);
    }

    private static BigInteger cipherPlainText(String plainTextInput, BigInteger e, BigInteger n) {
        BigInteger text = CryptographyUtils.toBigInteger(plainTextInput, PADDING);

        return CryptographyUtils.powerMod(text, e.intValue(), n);
    }

    private static String decipher(BigInteger privateKey, BigInteger cypheredText, BigInteger n) {
        BigInteger plainTextRep = CryptographyUtils.powerMod(cypheredText, privateKey.intValue(), n);
        return CryptographyUtils.toString(plainTextRep, PADDING);
    }

    public static void main(String[] args) {
        System.out.println("*** School book RSA ***");

        String totalBitsInput = requestInput("Enter the Total Bits for the RSA modulo (min: 16/max: 1024): ", (String s) -> {
            try {
                int v = Integer.parseInt(s);
                return v >= 16 && v <= 1024 && v % 8 == 0;
            } catch (NumberFormatException ignored) {}
            return false;
        });
        int totalBits = Integer.parseInt(totalBitsInput);
        int maxPlainTextLength = (totalBits - 8) / 8; // subtracting 8 bits reserved for padding

        String plainTextInput = requestInput(String.format("Enter the plain text (max len: %d): ", maxPlainTextLength),
                (String s) -> !s.isEmpty() && s.getBytes().length <= maxPlainTextLength);

        validate(totalBits, plainTextInput);

        BigInteger e = DEFAULT_E;
        BigInteger p = generatePrime(totalBits, e);
        BigInteger q = generatePrime(totalBits, e);
        BigInteger n = p.multiply(q);
        BigInteger totientN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger d = generatePrivateComponent(e, totientN);

        BigInteger cipheredTextRep = cipherPlainText(plainTextInput, e, n);
        String cipheredText = CryptographyUtils.toString(cipheredTextRep, null);

        System.out.printf("Public components [e: %s, n: %s]\n", e, n);
        System.out.printf("Private components [d: %s, n: %s (p: %s, q: %s)]\n", d, n, p, q);
        System.out.printf("Ciphered text: %s\n", cipheredText);

        System.out.println("Deciphering...");
        // we will assume 'n' is already supplied, and the ciphered text as well
        String privateKey = requestInput("\nEnter the private key: ",
                (String s) -> !s.isEmpty() && n.compareTo(BigInteger.valueOf(s.length())) > 0);
        String plainText = decipher(new BigInteger(privateKey), cipheredTextRep, n);

        System.out.println("Plain text deciphered: " + plainText);
    }

    /**
     * Verifies if the plain text fits into the total bits entered.
     *
     * @param totalBitsInput
     * @param plainTextInput
     */
    private static void validate(int totalBitsInput, String plainTextInput) {
        if (plainTextInput.getBytes().length * 8 > totalBitsInput)
            throw new IllegalArgumentException("Plain text entered doesn't into the total bits chosen");
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
