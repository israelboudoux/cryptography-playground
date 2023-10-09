package edu.boudoux.ecc;

import edu.boudoux.utils.CryptographyUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class EllipticCurveCryptographyTests {
    @Test
    public void shouldReturnPointAtInfinityWhenPointBeingAddedIsTheMirrorFromTheOtherOperand_fixed() {
        EllipticCurveCryptography ecc = new EllipticCurveCryptography(BigInteger.TWO, BigInteger.TWO, BigInteger.valueOf(17));

        Assert.assertEquals(EllipticCurveCryptography.Point.INFINITY,
                ecc.add(EllipticCurveCryptography.Point.of(BigInteger.valueOf(5), BigInteger.valueOf(16)),
                        EllipticCurveCryptography.Point.of(BigInteger.valueOf(5), BigInteger.ONE)));
    }

    @Test
    public void shouldAddTwoInfinityPoints() {
        EllipticCurveCryptography ecc = new EllipticCurveCryptography(BigInteger.TWO, BigInteger.TWO, BigInteger.valueOf(17));

        Assert.assertEquals(EllipticCurveCryptography.Point.INFINITY,
                ecc.add(EllipticCurveCryptography.Point.INFINITY, EllipticCurveCryptography.Point.INFINITY));
    }

    @Test
    public void shouldAddInfinityAndNonInfinityPoints() {
        EllipticCurveCryptography ecc = new EllipticCurveCryptography(BigInteger.TWO, BigInteger.TWO, BigInteger.valueOf(17));
        EllipticCurveCryptography.Point point = EllipticCurveCryptography.Point.of(BigInteger.valueOf(5), BigInteger.valueOf(16));

        Assert.assertEquals(point,
                ecc.add(EllipticCurveCryptography.Point.INFINITY, point));
        Assert.assertEquals(point,
                ecc.add(point, EllipticCurveCryptography.Point.INFINITY));
    }

    @Test
    public void shouldReturnInfinityForPointWithNoMirrorPoint() {
        EllipticCurveCryptography ecc = new EllipticCurveCryptography(BigInteger.TWO, BigInteger.TWO, BigInteger.valueOf(31));
        EllipticCurveCryptography.Point noMirrorPoint = EllipticCurveCryptography.Point.of(BigInteger.valueOf(28), BigInteger.ZERO);

        Assert.assertEquals(EllipticCurveCryptography.Point.INFINITY,
                ecc.add(noMirrorPoint, noMirrorPoint));

        ecc = new EllipticCurveCryptography(BigInteger.TWO, BigInteger.TWO, BigInteger.valueOf(197));
        noMirrorPoint = EllipticCurveCryptography.Point.of(BigInteger.valueOf(178), BigInteger.ZERO);

        Assert.assertEquals(EllipticCurveCryptography.Point.INFINITY,
                ecc.add(noMirrorPoint, noMirrorPoint));
    }

    @Test
    public void shouldPassECDSA() {
        // NIST parameters for Curve P-192 (fips 186-3 doc)
        BigInteger p = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
        BigInteger a = BigInteger.valueOf(3).negate();
        BigInteger b = new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16);
        BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

        EllipticCurveCryptography.Point generator = new EllipticCurveCryptography.Point(new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
                new BigInteger("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16));

        BigInteger privateKey = CryptographyUtils.generateNumber(BigInteger.TWO, n);
        EllipticCurveCryptography ecc = new EllipticCurveCryptography(a, b, p);
        EllipticCurveCryptography.Point publicKey = ecc.add(privateKey, generator);

        EllipticCurveDigitalSignatureAlgorithm.DomainParameters dp = EllipticCurveDigitalSignatureAlgorithm.dp(a, b, p, n, generator, publicKey);

        String message = "Hello world!";
        Pair<BigInteger, BigInteger> signature = EllipticCurveDigitalSignatureAlgorithm.sign(message, dp, privateKey);

        Assert.assertTrue(EllipticCurveDigitalSignatureAlgorithm.verify(message, signature, dp, publicKey));
    }
}
