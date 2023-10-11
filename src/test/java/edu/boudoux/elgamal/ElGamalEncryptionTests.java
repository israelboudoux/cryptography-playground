package edu.boudoux.elgamal;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class ElGamalEncryptionTests {
    @Test
    public void shouldVerifySignatureSuccessfully() {
        Pair<BigInteger, ElgamalEncryption.DomainParameters> key = ElgamalEncryption.generateKeyForSigning();
        
        String message = "Hello world!";
        Pair<BigInteger, BigInteger> signature = ElgamalEncryption.sign(message, key.getLeft(), key.getRight());

        Assert.assertTrue(ElgamalEncryption.verify(message, key.getRight(), signature));
    }
}
