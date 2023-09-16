package edu.boudoux.rsa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import edu.boudoux.util.CryptographyUtils;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Map;

public class SchoolBookRSATest {

    @Test
    public void shouldPassGeneratingPrimeTest() {
        for (int i = 1; i <= 10_000; i++) {
            BigInteger primeCandidate = SchoolBookRSA.generatePrime(16, SchoolBookRSA.DEFAULT_E, null);

            assertTrue(primeCandidate + " is not prime!!!", CryptographyUtils.isPrime2(primeCandidate));
        }
    }

    @Test
    public void shouldPassForHandCraftedGoodValues_16bitsModuloSize_singleValue() {
        BigInteger n = new BigInteger("41567");
        SchoolBookRSA.PubKey pubKey = new SchoolBookRSA.PubKey(new BigInteger("17"), n);
        SchoolBookRSA.PrivKey privKey = new SchoolBookRSA.PrivKey(new BigInteger("26633"), n);

        String expected = "a";
        BigInteger cipherText = SchoolBookRSA.cipherPlainText(expected, pubKey.e(), pubKey.n());
        String plainText = SchoolBookRSA.decipher(cipherText, privKey.d(), privKey.n());

        assertEquals(plainText, expected);
    }

    @Test
    public void shouldPassForHandCraftedGoodValues_16bitsModuloSize_ASCIIValues() {
        BigInteger n = new BigInteger("41567");
        SchoolBookRSA.PubKey pubKey = new SchoolBookRSA.PubKey(new BigInteger("17"), n);
        SchoolBookRSA.PrivKey privKey = new SchoolBookRSA.PrivKey(new BigInteger("26633"), n);

        byte[] b = new byte[1];
        for (byte i = 0; i < 127; i++) {
            b[0] = i;
            String expected = new String(b);
            BigInteger cipherText = SchoolBookRSA.cipherPlainText(expected, pubKey.e(), pubKey.n());
            String plainText = SchoolBookRSA.decipher(cipherText, privKey.d(), privKey.n());

            assertEquals(plainText, expected);
        }
    }

    @Test
    public void shouldPassForGeneratedValues_16bitsModuloSize() {
        Map.Entry<SchoolBookRSA.PubKey, SchoolBookRSA.PrivKey> keys = SchoolBookRSA.generateKeyComponents(16);
        byte[] b = new byte[1];
        for (byte i = 0; i < 127; i++) {
            b[0] = i;
            String expected = new String(b);
            BigInteger cipherText = SchoolBookRSA.cipherPlainText(expected, keys.getKey().e(), keys.getKey().n());
            String plainText = SchoolBookRSA.decipher(cipherText, keys.getValue().d(), keys.getValue().n());

            assertEquals(plainText, expected);
        }
    }

    @Test
    public void shouldPassForHandCraftedGoodValues_16bitsModuloSize_NonASCIIValues() {
        BigInteger n = new BigInteger("41567");
        SchoolBookRSA.PubKey pubKey = new SchoolBookRSA.PubKey(new BigInteger("17"), n);
        SchoolBookRSA.PrivKey privKey = new SchoolBookRSA.PrivKey(new BigInteger("26633"), n);

        byte[] b = new byte[1];
        for (byte i = -128; i < 0; i++) {
            b[0] = i;
            String expected = new String(b);
            BigInteger cipherText = SchoolBookRSA.cipherPlainText(expected, pubKey.e(), pubKey.n());
            String plainText = SchoolBookRSA.decipher(cipherText, privKey.d(), privKey.n());

            assertEquals(plainText, expected);
        }
    }
}
