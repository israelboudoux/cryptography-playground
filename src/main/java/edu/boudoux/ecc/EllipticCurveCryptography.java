package edu.boudoux.ecc;

import static edu.boudoux.utils.CryptographyUtils.*;

import java.math.BigInteger;
import java.util.*;

/**
 *
 * y^2 = x^3 + a * x + b (The Weiertrass equation)
 */
public class EllipticCurveCryptography {
    public static final BigInteger THREE = BigInteger.valueOf(3);

    /**
     * The value of the coefficient 'a'.
     */
    private BigInteger a;

    /**
     * The value of the coefficient 'b'.
     */
    private BigInteger b;

    /**
     * The prime number representing the finite field.
     */
    private BigInteger p;

    public EllipticCurveCryptography(BigInteger a, BigInteger b, BigInteger p) {
        if (a == null
                || p == null
                || ! isPrime(p)
                || lowerThanOrEqual(p, BigInteger.valueOf(3))) {
            throw new IllegalArgumentException("Invalid parameters");
        }

        // TODO calculate the discriminant!

        this.a = a;
        this.b = b != null ? b : BigInteger.ZERO;
        this.p = p;
    }

    public BigInteger a() {
        return a;
    }

    public BigInteger b() {
        return b;
    }

    public BigInteger p() {
        return p;
    }

    public record Point(BigInteger x, BigInteger y) {
        /**
         * The additive identity.
         */
        public static final Point INFINITY = new Point(null, null);

        public static Point of(BigInteger x, BigInteger y) {
            return new Point(x, y);
        }

        @Override
        public String toString() {
            return
                    this.equals(INFINITY) ?
                            "Point[Infinity]" :
                            "Point[" +
                                    "x=" + x +
                                    ", y=" + y +
                                    ']';
        }
    }

    public boolean isNotOnCurve(Point p) {
        return !p.equals(Point.INFINITY)
                    && !p.y().pow(2)
                             .mod(p())
                             .equals(
                                    p.x().pow(3)
                                            .add(a().multiply(p.x()))
                                            .add(b())
                                            .mod(p()));
    }

    /**
     * IF P_1 == P_2
     *   s = (2 * x_1^2 + a) / 2 * y_1 mod p
     * ELSE
     *   s = (y_2 - y_1) / (x_2 - x_1) mod p
     */
    private BigInteger s(Point p1, Point p2) {
        if (p1.equals(p2)) { // point doubling
            return THREE.multiply(p1.x().pow(2))
                        .add(a())
                        .multiply(mmi2(BigInteger.TWO.multiply(p1.y()).mod(p()), p()))
                        .mod(p());
        }

        // point addition
        return p2.y().subtract(p1.y())
                     .multiply(mmi2(p2.x().subtract(p1.x()).mod(p()), p()))
                     .mod(p());
    }

    /**
     * x_3 = s^2 - x_1 - x_2 mod p
     *
     * @param s
     * @param p1
     * @param p2
     * @return
     */
    private BigInteger x(BigInteger s, Point p1, Point p2) {
        return s.pow(2)
                .subtract(p1.x())
                .subtract(p2.x())
                .mod(p());
    }

    /**
     * y_3 = s * (x_1 - x_3) - y_1 mod p
     *
     * @param s
     * @param x_3
     * @param p1
     * @return
     */
    private BigInteger y(BigInteger s, BigInteger x_3, Point p1) {
        return s.multiply(p1.x().subtract(x_3))
                .subtract(p1.y())
                .mod(p());
    }

    /**
     *
     * @param p1
     * @param p2
     * @return
     */
    public Point add(Point p1, Point p2) {
        if (isNotOnCurve(p1) || isNotOnCurve(p2)) {
            throw new IllegalArgumentException("Invalid points (not on curve)!");
        }

        if (p1.equals(Point.INFINITY)) {
            return p2;
        } else if (p2.equals(Point.INFINITY)) {
            return p1;
        }

        BigInteger s = s(p1, p2);
        BigInteger x_3 = x(s, p1, p2);

        if (! p1.equals(p2)
                && p1.x().equals(p2.x())
                && p1.y().add(p2.y()).mod(p()).equals(BigInteger.ZERO)) {
            return Point.INFINITY;
        }

        Point result = Point.of(x_3, y(s, x_3, p1));
        if (isNotOnCurve(result)) {
            return Point.INFINITY;
        }

        return result;
    }

    public Point add(BigInteger xTimes, Point generator) {
        Point result = generator;

        int totalBitsX = xTimes.bitLength();
        for (int i = totalBitsX - 2; i >= 0; i--) {
            result = add(result, result);
            if (xTimes.shiftRight(i).mod(BigInteger.TWO).equals(BigInteger.ONE)) {
                result = add(result, generator);
            }
        }

        return result;
    }

    /**
     * Depending on the size of 'p', this method can take ages to finish processing or might result in OutOfMemoryError.
     *
     * @return
     */
    public List<Point> findAllPoints() {
        final List<Point> result = new ArrayList<>();
        final Map<BigInteger, BigInteger> resultsMapForY = new HashMap<>();
        final BigInteger minusOne = BigInteger.ONE.negate();

        result.add(Point.INFINITY);

        BigInteger x = BigInteger.ZERO;
        do {
            BigInteger modXResult = x.pow(3)
                            .add(a().multiply(x))
                            .add(b())
                            .mod(p());

            if (modXResult.equals(BigInteger.ZERO)) {
                result.add(Point.of(x, BigInteger.ZERO));
            } else if (modXResult.equals(BigInteger.ONE)) {
                result.add(Point.of(x, BigInteger.ONE));
                result.add(Point.of(x, minusOne.add(p())));
            } else {
                BigInteger y = calculateY(modXResult, resultsMapForY);
                if (! y.equals(minusOne)) {
                    result.add(Point.of(x, y));
                    result.add(Point.of(x, y.negate().add(p())));
                }
            }

            x = x.add(BigInteger.ONE);
        } while (lowerThan(x, p()));

        return Collections.unmodifiableList(result);
    }

    private BigInteger calculateY(BigInteger r, Map<BigInteger, BigInteger> resultsMapForY) {
        BigInteger result;
        if ((result = resultsMapForY.get(r)) != null) {
            return result;
        }

        result = BigInteger.TWO;
        do {
            if (result.pow(2).mod(p()).equals(r)) {
                resultsMapForY.put(r, result);
                return result;
            }

            result = result.add(BigInteger.ONE);
        } while (lowerThan(result, p()));

        result = BigInteger.ONE.negate();

        resultsMapForY.put(r, result);

        return result;
    }

    public static void main(String[] args) {
        EllipticCurveCryptography ecc = new EllipticCurveCryptography(BigInteger.TWO, BigInteger.TWO, BigInteger.valueOf(17));

        List<Point> pointList = ecc.findAllPoints();
        System.out.println("Total points found: " + pointList.size() + "\n");
        pointList.forEach(System.out::println);
    }
}
