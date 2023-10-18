package edu.boudoux.dsa;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;

import static edu.boudoux.utils.CryptographyUtils.*;

public class DigitalSignatureScheme {

    // The following numbers should be at least 1023/1024 for a good security level
    private static final BigInteger P_MIN_BOUND = BigInteger.TWO.pow(15);
    private static final BigInteger P_MAX_BOUND = BigInteger.TWO.pow(16);

    // The following numbers should be at least 159/160 for a good security level
    private static final BigInteger Q_MIN_BOUND = BigInteger.TWO.pow(7);
    private static final BigInteger Q_MAX_BOUND = BigInteger.TWO.pow(8);

    public record DomainParameters(BigInteger p, BigInteger q, BigInteger generator, BigInteger publicKey) {}

    public static Pair<BigInteger, DomainParameters> setup() {
        BigInteger p = null, q;
        do {
            q = generatePrimeOpenBounds(Q_MIN_BOUND, Q_MAX_BOUND);
            for (int i = 1; i <= 4096; i++) {
                BigInteger m = generatePrimeOpenBounds(P_MIN_BOUND, P_MAX_BOUND);
                BigInteger m_ = m.mod(q.multiply(BigInteger.TWO));
                BigInteger pMinusOne = m.subtract(m_);
                if (isProbablePrime(pMinusOne.add(BigInteger.ONE))) {
                    p = pMinusOne.add(BigInteger.ONE);
                    break;
                }
            }
        } while (p == null);

        // This generator must have ord(g) = q.
        // IMPORTANT! this method isn't trustable, since it doesn't test all elements in q if it is too big
        BigInteger generator = getGenerator(p, q);

        BigInteger d = generateNumber(BigInteger.ONE, q);
        BigInteger publicKey = powerMod(generator, d, p);

        return Pair.of(d, new DomainParameters(p, q, generator, publicKey));
    }

    public static Pair<BigInteger, BigInteger> sign(String message, BigInteger privateKey, DomainParameters domainParameters) {
        BigInteger r;
        BigInteger s;

        do {
            BigInteger ephemeralKey = generateNumber(BigInteger.ONE, domainParameters.q());
            BigInteger ephemeralKeyInverse = ephemeralKey.modInverse(domainParameters.q());

            String messageDigest = digest(message, domainParameters.q());
            BigInteger messageDigestBigIntRep = new BigInteger(messageDigest, 16);

            r = domainParameters.generator().modPow(ephemeralKey, domainParameters.p())
                    .mod(domainParameters.q());
            s = ephemeralKeyInverse.multiply(messageDigestBigIntRep.add(privateKey.multiply(r)))
                    .mod(domainParameters.q());
        } while (r.equals(BigInteger.ZERO) || s.equals(BigInteger.ZERO));

        return Pair.of(r, s);
    }

    private static String digest(String message, BigInteger q) {
        String messageDigest = DigestUtils.sha1Hex(message);
        int hexDigitsInQ = q.bitLength() / 4;

        return messageDigest.substring(0, Math.min(hexDigitsInQ, messageDigest.length()));
    }

    public static boolean verify(String message, DomainParameters domainParameters, Pair<BigInteger, BigInteger> signature) {
        BigInteger r = signature.getLeft();
        BigInteger s = signature.getRight();
        BigInteger q = domainParameters.q();

        if (lowerThan(r, BigInteger.ONE) || greaterThan(r, q)
                || lowerThan(s, BigInteger.ONE) || greaterThan(s, q)) {
            return false;
        }

        String messageDigest = digest(message, domainParameters.q());
        BigInteger messageDigestBigIntRep = new BigInteger(messageDigest, 16);

        BigInteger w = s.modInverse(q);
        BigInteger u1 = w.multiply(messageDigestBigIntRep).mod(q);
        BigInteger u2 = w.multiply(r).mod(q);

        BigInteger p = domainParameters.p();
        BigInteger generator = domainParameters.generator();
        BigInteger pubKey = domainParameters.publicKey();

        BigInteger v = generator.modPow(u1, p)
                                .multiply(pubKey.modPow(u2, p))
                                .mod(p)
                                .mod(q);

        return v.equals(r.mod(q));
    }
}
