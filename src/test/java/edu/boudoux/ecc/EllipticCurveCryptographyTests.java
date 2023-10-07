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
}
