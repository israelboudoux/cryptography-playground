package edu.boudoux.mac;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class CbcMacTests {
    private final String message = "Hello world!";
    private final String key = "Xpt0_%.-15r@9588";

    @Test
    public void shouldPassVerifyingMac() {
        Pair<String, BigInteger> result = CbCMac.encode(message, key);

        Assert.assertTrue("Verification failed when it was supposed to pass", CbCMac.verify(message, key, result.getRight(), result.getLeft()));
    }

    @Test
    public void shouldPassVerifyingMacBigMessage() {
        String message_ = message.repeat(31);
        Pair<String, BigInteger> result = CbCMac.encode(message_, key);

        Assert.assertTrue("Verification failed when it was supposed to pass", CbCMac.verify(message_, key, result.getRight(), result.getLeft()));
    }

    @Test
    public void shouldFailVerifyingForAlteredMessage() {
        Pair<String, BigInteger> result = CbCMac.encode(message, key);

        Assert.assertFalse("Verification passed when expected to fail", CbCMac.verify(message + "!!!", key, result.getRight(), result.getLeft()));
    }
}
