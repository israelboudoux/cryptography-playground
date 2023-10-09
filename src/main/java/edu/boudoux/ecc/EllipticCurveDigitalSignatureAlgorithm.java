package edu.boudoux.ecc;

import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;

import static edu.boudoux.utils.CryptographyUtils.*;

/**
 * ECDSA
 */
public class EllipticCurveDigitalSignatureAlgorithm {

    public static record DomainParameters(BigInteger a,
                                          BigInteger b,
                                          BigInteger p,
                                          BigInteger n,
                                          EllipticCurveCryptography.Point generator,
                                          EllipticCurveCryptography.Point publicKey) {}

    public static DomainParameters dp(BigInteger a,
                                      BigInteger b,
                                      BigInteger p,
                                      BigInteger n,
                                      EllipticCurveCryptography.Point generator,
                                      EllipticCurveCryptography.Point publicKey) {
        return new DomainParameters(a, b, p, n, generator, publicKey);
    }

    /**
     * domain parameters: a, b, G, p, Y, n (n is a prime s.t. n * G = O)
     * Signing:
     *  select a random x s.t. 1 <= x < n (private key)
     *  calculate public key: Y = x * G
     *  Generate a one-time value 'k' s.t. 0 < k < n (should be used only once)
     *  hash the message: H = hash(M)
     *  r = (k * G)_x mod n (_x means to pick the x coordinate)
     *  s = k^-1 * (H + x * r) mod n
     *  (r, s) is the signature!
     */
    public static Pair<BigInteger, BigInteger> sign(String message, DomainParameters domainParameters, BigInteger privateKey) {
        if (lowerThan(privateKey, BigInteger.ONE) || greaterThanOrEqual(privateKey, domainParameters.n())) {
            throw new IllegalArgumentException("Invalid private key");
        }

        EllipticCurveCryptography ecc = new EllipticCurveCryptography(domainParameters.a(), domainParameters.b(), domainParameters.p());

        BigInteger k = generateNumber(BigInteger.ONE, domainParameters.n());
        String messageHash = digest(message);
        BigInteger r = ecc.add(k, domainParameters.generator()).x().mod(domainParameters.n());
        BigInteger kInverse = mmi2(k, domainParameters.n());
        BigInteger s = kInverse.multiply(new BigInteger(messageHash, 16).add(privateKey.multiply(r))).mod(domainParameters.n());

        return Pair.of(r, s);
    }

    /**
     * Verifying:
     *  hash the message: H = hash(M)
     *  w = s^-1 mod n
     *  u_1 = H * w mod n
     *  u_2 = r * w mod n
     *  (x, y) = u_1 * G + u_2 * Y
     *  if r === x mod n; signature is valid
     */
    public static boolean verify(String message,
                          Pair<BigInteger, BigInteger> signature,
                          DomainParameters domainParameters,
                          EllipticCurveCryptography.Point publicKey) {
        BigInteger r = signature.getLeft();
        BigInteger s = signature.getRight();

        BigInteger w = mmi2(s, domainParameters.n());

        String messageHash = digest(message);

        BigInteger u1 = new BigInteger(messageHash, 16).multiply(w).mod(domainParameters.n());
        BigInteger u2 = r.multiply(w).mod(domainParameters.n());

        EllipticCurveCryptography ecc = new EllipticCurveCryptography(domainParameters.a(), domainParameters.b(), domainParameters.p());
        EllipticCurveCryptography.Point pointU1 = ecc.add(u1, domainParameters.generator());
        EllipticCurveCryptography.Point pointU2 = ecc.add(u2, publicKey);

        EllipticCurveCryptography.Point resultingPoint = ecc.add(pointU1, pointU2);

        return resultingPoint.x().mod(domainParameters.n()).equals(r);
    }
}
