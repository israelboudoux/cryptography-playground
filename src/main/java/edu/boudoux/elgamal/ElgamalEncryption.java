package edu.boudoux.elgamal;

import edu.boudoux.utils.CryptographyUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;

import static edu.boudoux.utils.CryptographyUtils.*;

public class ElgamalEncryption {

    private static final int MODULO_BITS = 128; // For a good security level, this would need to be at least 1024 bits

    public static record DomainParameters(BigInteger p, BigInteger generator, BigInteger publicKey) {}

    public static class Actor {
        private final String name;

        private final BigInteger privateKey;

        private final DomainParameters publicKey;

        public Actor(String name) {
            this.name = name;

            BigInteger p = generatePrime(MODULO_BITS);
            BigInteger g = getGenerator(p);
            BigInteger privateKey = generateNumber(BigInteger.TWO, p.subtract(BigInteger.ONE));
            BigInteger publicKey = powerMod(g, privateKey, p);

            this.privateKey = privateKey;
            this.publicKey = new DomainParameters(p, g, publicKey);
        }

        public String getName() {
            return name;
        }

        public DomainParameters getPublicKey() {
            return publicKey;
        }

        private BigInteger getPrivateKey() {
            return privateKey;
        }

        public void sendMessage(String message, Actor recipient) {
            DomainParameters recipientPublicKey = recipient.getPublicKey();
            BigInteger messageBigIntRep = toBigInteger(message);

            if (greaterThanOrEqual(messageBigIntRep, recipientPublicKey.p())) {
                throw new IllegalArgumentException(String.format("Too big message for the current setup (max bits: %d)", recipientPublicKey.p().bitLength()));
            }

            BigInteger ephemeralKey = generateNumber(BigInteger.TWO, recipientPublicKey.p().subtract(BigInteger.ONE));
            BigInteger myEphemeralPublicKey = powerMod(recipientPublicKey.generator(), ephemeralKey, recipientPublicKey.p());

            BigInteger maskingKey = powerMod(recipientPublicKey.publicKey(), ephemeralKey, recipientPublicKey.p());
            BigInteger maskedMessageBigIntRep = messageBigIntRep.multiply(maskingKey).mod(recipientPublicKey.p());
            String maskedMessage = maskedMessageBigIntRep.toString(16);

            System.out.printf("Hello! %s speaking here. I'm sending the following message to %s: %s%n", name, recipient.getName(), maskedMessage);

            recipient.handleIncomingMessage(maskedMessage, myEphemeralPublicKey);
        }

        private void handleIncomingMessage(String maskedMessage, BigInteger senderPublicKey) {
            BigInteger maskingKey = powerMod(senderPublicKey, getPrivateKey(), getPublicKey().p());
            BigInteger maskingKeyInverse = mmi2(maskingKey, getPublicKey().p());
            BigInteger maskedMessageBigIntRep = new BigInteger(maskedMessage, 16);
            BigInteger messageBigIntRep = maskedMessageBigIntRep.multiply(maskingKeyInverse).mod(getPublicKey().p());
            String unmaskedMessage = CryptographyUtils.toString(messageBigIntRep, getPublicKey().p());

            System.out.printf("Hello! %s speaking here. I just received the following message: %s%n", getName(), unmaskedMessage);
        }

        @Override
        public String toString() {
            return "Actor{" +
                    "name='" + name + '\'' +
                    ", privateKey=" + privateKey +
                    ", publicKey=" + publicKey +
                    '}';
        }
    }

    public static Pair<BigInteger, DomainParameters> generateKeyForSigning() {
        BigInteger p = generatePrime(MODULO_BITS);
        BigInteger g = getGenerator(p);
        BigInteger privateKey = generateNumber(BigInteger.TWO, p.subtract(BigInteger.ONE));
        BigInteger publicKey = powerMod(g, privateKey, p);

        return Pair.of(privateKey, new DomainParameters(p, g, publicKey));
    }

    public static String digest(String message) {
        String messageDigest = DigestUtils.sha1Hex(message);

        return MODULO_BITS > messageDigest.length() * 4 ? messageDigest : messageDigest.substring(0, messageDigest.length() / 4 - 1);
    }

    public static Pair<BigInteger, BigInteger> sign(String message, BigInteger privateKey, DomainParameters domainParameters) {
        String messageDigest = digest(message);
        BigInteger messageBigIntRep = new BigInteger(messageDigest, 16);

        BigInteger pMinusOne = domainParameters.p().subtract(BigInteger.ONE);
        BigInteger ephemeralKey = generateEphemeralKeyForSigning(pMinusOne);
        BigInteger ephemeralKeyInverse = mmi2(ephemeralKey, pMinusOne);
        BigInteger r = powerMod(domainParameters.generator(), ephemeralKey, domainParameters.p());
        BigInteger s = messageBigIntRep.subtract(privateKey.multiply(r))
                .multiply(ephemeralKeyInverse)
                .mod(pMinusOne);

        return Pair.of(r, s);
    }

    public static BigInteger generateEphemeralKeyForSigning(BigInteger modulo) {
        BigInteger result;
        do {
            result = generateNumber(BigInteger.TWO, modulo);
        } while (! gcd(result, modulo).equals(BigInteger.ONE));

        return result;
    }

    public static boolean verify(String message, DomainParameters domainParameters, Pair<BigInteger, BigInteger> signature) {
        BigInteger r = signature.getLeft();
        BigInteger s = signature.getRight();
        BigInteger p = domainParameters.p();
        BigInteger t = powerMod(domainParameters.publicKey(), r, p).multiply(powerMod(r, s, p)).mod(p);

        String messageDigest = digest(message);
        BigInteger messageBigIntRep = new BigInteger(messageDigest, 16);

        return t.equals(powerMod(domainParameters.generator(), messageBigIntRep, p));
    }

    public static void main(String[] args) {
        Actor alice = new Actor("Alice");
        Actor bob = new Actor("Bob");

        String message = "Hello world!";
        System.out.printf("Sending the message '%s' from '%s' to '%s'%n", message, alice, bob);

        alice.sendMessage(message, bob);
    }
}
