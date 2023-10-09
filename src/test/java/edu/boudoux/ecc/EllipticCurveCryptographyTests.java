package edu.boudoux.ecc;

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
}
