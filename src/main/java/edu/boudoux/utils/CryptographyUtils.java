package edu.boudoux.utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.util.stream.IntStream;

public final class CryptographyUtils {

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
     * This algorithm extends Euclid's to return the Modular Multiplicative Inverse (MMI) using Bezout's Identity.
     * A GCD can be represented as a linear combination of the operands (GCD = aX + bY | X,Y are in the Z set),the X
     * value it is the MMI between A and B.
     *
     * @param a
     * @param b
     * @return the (MMI) between A and B,otherwise returns -1,since the MMI only exists for _relatively prime_ operands.
     */
    public static long mmi2(long a,long b) {
        assert b > 0;

        long r = a % b;
        long x = 1,y = (r - a) / b;
        long a_1 = b,b_1 = r;

        if (r == 0) return -1;

        long x_1 = 0;
        long y_1 = 0,y_2;

        int i = 1;
        while(b_1 != 0 && b_1 != 1) {
            r = a_1 % b_1;
            y_2 = (-a_1 + r) / b_1;

            if (i++ % 2 == 0) {
                x = x + y_2 * x_1;
                y = y + y_2 * y_1;
            } else {
                x_1 = x_1 + y_2 * x;
                y_1 = y_1 + y_2 * y;
            }

            a_1 = b_1;
            b_1 = r;
        }

        if (b_1 != 1) return -1;

        long result = (i - 1) % 2 == 0 ? x : x_1;

        if (result < 0) {
            return result + b;
        }

        return result;
    }

    public static boolean greaterThan(BigInteger a, BigInteger b) {
        return a.compareTo(b) > 0;
    }

    public static boolean lowerThanOrEqual(BigInteger a, BigInteger b) {
        return a.compareTo(b) <= 0;
    }

    public static boolean greaterThanOrEqual(BigInteger a, BigInteger b) {
        return a.compareTo(b) >= 0;
    }

    public static boolean lowerThan(BigInteger a, BigInteger b) {
        return a.compareTo(b) < 0;
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

    public static void main(String[] args) {
        // 197 / q: 219
        System.out.println(isPrime2(new BigInteger("219")));

        BigInteger p = new BigInteger("223");
        BigInteger q = new BigInteger("197");
        BigInteger e = new BigInteger("17");
        BigInteger paddedPlainText = new BigInteger("32865");

        BigInteger n = p.multiply(q);
        BigInteger totient = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

         if(gcd(e, totient).longValue() != 1 || gcd(e, p.subtract(BigInteger.ONE)).longValue() != 1 || gcd(e, q.subtract(BigInteger.ONE)).longValue() != 1)
             throw new IllegalStateException("GCD error");

        BigInteger d = mmi2(e, totient);
        System.out.println("d: " + d + ", n: " + n);

        BigInteger cipher = powerMod(paddedPlainText, e, n);
        System.out.println(cipher);

        BigInteger plain = powerMod(cipher, d, n);
        System.out.println("===> " + plain.equals(paddedPlainText) + " (" + plain + ")");
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
    public static boolean isPrime2(BigInteger p) {
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
        long[] probeList = random.longs(maxProbes,2, p.longValue()).toArray();
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

    /**
     * Uses brute force by verifying if every positive element lower than the value has a MMI.
     *
     * @param value
     * @return
     */
    public static boolean isPrime(long value) {
        for (long i = 2; i < value; i++) {
            if (mmi2(i,value) == -1) return false;
        }

        return true;
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
}
