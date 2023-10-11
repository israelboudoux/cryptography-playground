package edu.boudoux.elgamal;

import edu.boudoux.utils.CryptographyUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static edu.boudoux.utils.CryptographyUtils.*;

public class ElgamalEncryption {

    public static record PublicKey (BigInteger p, BigInteger generator, BigInteger publicKey) {}

    public static class Actor {
        private String name;

        private BigInteger privateKey;

        private PublicKey publicKey;

        public Actor(String name) {
            this.name = name;

            BigInteger p = generatePrime(128); // For a good security, this would need to be at least 1024 bits
            BigInteger g = getGenerator(p);
            BigInteger privateKey = generateNumber(BigInteger.TWO, p.subtract(BigInteger.ONE));
            BigInteger publicKey = powerMod(g, privateKey, p);

            this.privateKey = privateKey;
            this.publicKey = new PublicKey(p, g, publicKey);
        }

        public String getName() {
            return name;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        private BigInteger getPrivateKey() {
            return privateKey;
        }

        public void sendMessage(String message, Actor recipient) {
            PublicKey recipientPublicKey = recipient.getPublicKey();
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

    public static void main(String[] args) {
        Actor alice = new Actor("Alice");
        Actor bob = new Actor("Bob");

        String message = "Hello world!";
        System.out.printf("Sending the message '%s' from '%s' to '%s'%n", message, alice, bob);

        alice.sendMessage(message, bob);
    }
}
