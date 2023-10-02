package edu.boudoux.rsa;

import edu.boudoux.utils.CryptographyUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

public class SchoolbookRSATest {

    @Test
    public void shouldPassGeneratingPrimeTest() {
        for (int i = 1; i <= 10_000; i++) {
            BigInteger primeCandidate = SchoolbookRSA.generatePrime(16, SchoolbookRSA.DEFAULT_E, null);

            assertTrue(primeCandidate + " is not prime!!!", CryptographyUtils.isPrime(primeCandidate));
        }
    }

    @Test
    public void shouldPassForHandCraftedGoodValues_16bitsModuloSize_singleValue() {
        BigInteger n = new BigInteger("41567");
        SchoolbookRSA.PubKey pubKey = new SchoolbookRSA.PubKey(new BigInteger("17"), n);
        SchoolbookRSA.PrivKey privKey = new SchoolbookRSA.PrivKey(new BigInteger("26633"), n);

        String expected = "a";
        String cipherText = SchoolbookRSA.cipherPlainText(expected, pubKey.e(), pubKey.n());
        String plainText = SchoolbookRSA.decipher(cipherText, privKey.d(), privKey.n());

        assertEquals(plainText, expected);
    }

    @Test
    public void shouldPassForHandCraftedGoodValues_16bitsModuloSize_ASCIIValues() {
        BigInteger n = new BigInteger("41567");
        SchoolbookRSA.PubKey pubKey = new SchoolbookRSA.PubKey(new BigInteger("17"), n);
        SchoolbookRSA.PrivKey privKey = new SchoolbookRSA.PrivKey(new BigInteger("26633"), n);

        byte[] b = new byte[1];
        for (byte i = 0; i < 127; i++) {
            b[0] = i;
            String expected = new String(b);
            String cipherText = SchoolbookRSA.cipherPlainText(expected, pubKey.e(), pubKey.n());
            String plainText = SchoolbookRSA.decipher(cipherText, privKey.d(), privKey.n());

            assertEquals(plainText, expected);
        }
    }

    @Test
    public void shouldPassForGeneratedValues_16bitsModuloSize() {
        for (int count = 1; count <= 10; count++) {
            Pair<SchoolbookRSA.PubKey, SchoolbookRSA.PrivKey> keys = SchoolbookRSA.generateKeyComponents(16);
            byte[] b = new byte[1];
            for (byte i = 0; i < 127; i++) {
                b[0] = i;
                String expected = new String(b, 0, 1, StandardCharsets.UTF_8);
                String cipherText = SchoolbookRSA.cipherPlainText(expected, keys.getKey().e(), keys.getKey().n());
                String plainText = SchoolbookRSA.decipher(cipherText, keys.getValue().d(), keys.getValue().n());

                assertEquals("failed for byte value '" + i + "'", plainText, expected);
            }
        }
    }

    @Test
    public void shouldPassForHandCraftedGoodValues_16bitsModuloSize_NonASCIIValues() {
        byte[] b = new byte[1];
        for (byte i = -128; i < 0; i++) {
            b[0] = i;
            String expected = new String(b);
            int moduloSize = expected.getBytes(StandardCharsets.UTF_8).length * 8 + 8; // adding 8bits to guarantee the modulo size supports the plain text
            Pair<SchoolbookRSA.PubKey, SchoolbookRSA.PrivKey> keyComp = SchoolbookRSA.generateKeyComponents(moduloSize);

            String cipherText = SchoolbookRSA.cipherPlainText(expected, keyComp.getKey().e(), keyComp.getKey().n());
            String plainText = SchoolbookRSA.decipher(cipherText, keyComp.getValue().d(), keyComp.getValue().n());

            assertEquals(String.format("Failed for iteration %d (n: %s, d: %s)", i, keyComp.getValue().n(), keyComp.getValue().d()), plainText, expected);
        }
    }

    @Test
    public void shouldPassForGeneratedValues_moduliFrom32To1024() {
        for(int moduloSize = 32; moduloSize <= 1024; moduloSize += 8) {
           Pair<SchoolbookRSA.PubKey, SchoolbookRSA.PrivKey> keyComp = SchoolbookRSA.generateKeyComponents(moduloSize);

            String expected = new String(new byte[] {-128});

            String cipherText = SchoolbookRSA.cipherPlainText(expected, keyComp.getKey().e(), keyComp.getKey().n());
            String plainText = SchoolbookRSA.decipher(cipherText, keyComp.getValue().d(), keyComp.getValue().n());

            assertEquals(plainText, expected);
        }
    }

    @Test
    public void shouldPassForMessageCorrectlySigned() {
        Pair<SchoolbookRSA.PubKey, SchoolbookRSA.PrivKey> keyComp = SchoolbookRSA.generateKeyComponents(512);

        String message = "testing message...";
        String signedMessage = SchoolbookRSA.sign(message, keyComp.getValue().d(), keyComp.getValue().n());

        assertTrue(SchoolbookRSA.verify(message, signedMessage, keyComp.getKey().e(), keyComp.getKey().n()));
    }

    @Test
    public void shouldFailForMessageChanged() {
        Pair<SchoolbookRSA.PubKey, SchoolbookRSA.PrivKey> keyComp = SchoolbookRSA.generateKeyComponents(512);

        String message = "I testify you own me $1000!";
        String signedMessage = SchoolbookRSA.sign(message, keyComp.getValue().d(), keyComp.getValue().n());

        assertFalse(SchoolbookRSA.verify("I testify you own me $100!", signedMessage, keyComp.getKey().e(), keyComp.getKey().n()));
    }
}
