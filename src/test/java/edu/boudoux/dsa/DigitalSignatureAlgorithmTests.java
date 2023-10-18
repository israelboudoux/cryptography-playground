package edu.boudoux.dsa;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

public class DigitalSignatureAlgorithmTests {
    private Pair<BigInteger, DigitalSignatureScheme.DomainParameters> keyComponents;

    @Before
    public void setup() {
        keyComponents = DigitalSignatureScheme.setup();
    }

    @Test
    public void shouldPassSignatureVerification() {
        String message = "Hello world!";

        Pair<BigInteger, BigInteger> signature = DigitalSignatureScheme.sign(message, keyComponents.getLeft(), keyComponents.getRight());

        System.out.println(keyComponents);
        Assert.assertTrue(String.format("Signature failed for parameters: %s", keyComponents),
                DigitalSignatureScheme.verify(message, keyComponents.getRight(), signature));
    }
}
