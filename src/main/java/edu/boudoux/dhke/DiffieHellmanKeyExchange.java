package edu.boudoux.dhke;

import edu.boudoux.utils.CryptographyUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.tuple.Pair;
import java.math.BigInteger;

public class DiffieHellmanKeyExchange {

    static class Actor {
        private final String name;

        private final BigInteger p;
        private final BigInteger generator;

        private BigInteger privateKey;

        private BigInteger publicKey;

        public Actor(String name, Pair<BigInteger, BigInteger> domainParameters) {
            this.name = name;
            this.p = domainParameters.getLeft();
            this.generator = domainParameters.getRight();

            Pair<BigInteger, BigInteger> keys = DiffieHellmanKeyExchange.generateKeys(domainParameters);

            this.publicKey = keys.getLeft();
            this.privateKey = keys.getRight();
        }

        public String getName() {
            return name;
        }

        public BigInteger getPublicKey() {
            return publicKey;
        }

        public void sendMessage(String message, Actor to) {
            // Gets the PubKey from the destination
            BigInteger destinationPublicKey = to.getPublicKey();

            BigInteger secretBigInteger = getPubKeyOrSecret(this.privateKey, destinationPublicKey, p);
            String secretString = digest(secretBigInteger);
            String cipherText = CryptographyUtils.aesEncryption(message, secretString);

            System.out.printf("Hello! %s speaking here. I'm sending the following message to %s: %s%n", name, to.getName(), cipherText);

            // Sends the message along with its own PubKey
            to.handleIncomingMessage(cipherText, this.publicKey);
        }

        private String digest(BigInteger value) {
            return DigestUtils.sha256Hex(value.toString());
        }

        private void handleIncomingMessage(String message, BigInteger partyPublicKey) {
            BigInteger secretBigInteger = getPubKeyOrSecret(this.privateKey, partyPublicKey, this.p);
            String secretString = digest(secretBigInteger);

            String decryptedMessage = CryptographyUtils.aesDecryption(message, secretString);

            System.out.printf("Hello! %s speaking here. I just received the following message: %s%n", this.getName(), decryptedMessage);
        }
    }

    /**
     * Performs the setup which is the phase where a prime number is generated and a primitive element in the set Zp*
     * is picked up
     *
     * @return a pair consisting of a prime number (L) and the generator (R) in the set.
     */
    public static Pair<BigInteger, BigInteger> setup(int totalBits) {
        final BigInteger p = CryptographyUtils.generatePrime(totalBits);

        final BigInteger generator = CryptographyUtils.getGenerator(p);

        return Pair.of(p, generator);
    }

    /**
     * Generates the private key in the range {2, ..., p - 2} (inclusive)
     *
     * @param p
     * @return
     */
    public static BigInteger generatePrivateKey(BigInteger p) {
        return CryptographyUtils.generateNumber(BigInteger.TWO, p.subtract(BigInteger.ONE));
    }

    /**
     * This method can be used to generate the public key and to return the secret value.
     *
     * @param key
     * @param generatorOrPubKey
     * @param p
     * @return
     */
    public static BigInteger getPubKeyOrSecret(BigInteger key, BigInteger generatorOrPubKey, BigInteger p) {
        return CryptographyUtils.powerMod(generatorOrPubKey, key, p);
    }

    public static void main(String[] args) {
        /*
         * This is the first step in the DHKE, the generation of the parameters, also referred as 'Domain Parameters'. Tney
         * are public and will be shared between the communicating parts in order to allow them to generate their keys.
         */
        Pair<BigInteger, BigInteger> domainParameters = setup(16);

        /*
         * In the second step the parts generate and exchange the Public Keys in order to extract the secret that will be
         * used to encrypt/decrypt messages by using a block cipher (e.g. DES, AES, etc.).
         */
        Actor alice = new Actor("Alice", domainParameters);
        Actor bob = new Actor("Bob", domainParameters);

        String myMessage = "Hello world!";

        alice.sendMessage(myMessage, bob);
    }

    /**
     * Generates the public and private keys.
     *
     * @return the Public Key (L) and the Private Key (R)
     */
    private static Pair<BigInteger, BigInteger> generateKeys(Pair<BigInteger, BigInteger> domainParameters) {
       BigInteger privatekey = generatePrivateKey(domainParameters.getLeft());
       BigInteger publicKey = getPubKeyOrSecret(privatekey, domainParameters.getRight(), domainParameters.getLeft());

       return Pair.of(publicKey, privatekey);
    }
}
