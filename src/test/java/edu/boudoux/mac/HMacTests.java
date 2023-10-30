package edu.boudoux.mac;

import org.junit.Assert;
import org.junit.Test;

public class HMacTests {

    private final String message = "Hello world!";
    private final String key = "xpto";

    @Test
    public void shouldSucceedVerifyingHMac() {
        String mac = HMac.encode(message, key);

        Assert.assertTrue("Verification failed when it was supposed to pass", HMac.verify(message, key, mac));
    }

    @Test
    public void shouldFailVerifyingForAlteredMessage() {
        String mac = HMac.encode(message, key);

        Assert.assertFalse("Verification passed when expected to fail", HMac.verify(message + "!!!", key, mac));
    }
}
