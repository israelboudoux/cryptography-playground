package edu.boudoux.ecc;

import org.apache.commons.codec.digest.DigestUtils;

import java.math.BigInteger;

import static edu.boudoux.utils.CryptographyUtils.*;

public class ActorECDH {
    private String name;

    private DomainParameters domainParameters;

    private EllipticCurveCryptography ecc;

    private BigInteger privateKey;

    private EllipticCurveCryptography.Point publicKey;

    public static record DomainParameters(BigInteger a, BigInteger b, BigInteger p, EllipticCurveCryptography.Point generator) {}

    public ActorECDH(String name, DomainParameters domainParameters) {
        this.name = name;
        this.domainParameters = domainParameters;

        this.ecc = new EllipticCurveCryptography(domainParameters.a(), domainParameters.b(), domainParameters.p());

        this.privateKey = generateNumber(BigInteger.TWO, domainParameters.p());
        this.publicKey = this.ecc.add(this.privateKey, domainParameters.generator());
    }

    public String getName() {
        return name;
    }

    public DomainParameters getDomainParameters() {
        return domainParameters;
    }

    public EllipticCurveCryptography.Point getPublicKey() {
        return publicKey;
    }

    private String digest(BigInteger value) {
        return DigestUtils.sha256Hex(value.toString());
    }

    public void sendMessage(String message, ActorECDH recipient) {
        EllipticCurveCryptography.Point recipientPublicKey = recipient.getPublicKey();
        EllipticCurveCryptography.Point pointSecret = ecc.add(this.privateKey, recipientPublicKey);

        String secretString = digest(pointSecret.x());
        String cipherText = aesEncryption(message, secretString);

        System.out.printf("Hello! %s speaking here. I'm sending the following message to %s: %s%n", name, recipient.getName(), cipherText);

        // Sends the message along with its own PubKey
        recipient.handleIncomingMessage(cipherText, this.publicKey);
    }

    private void handleIncomingMessage(String message, EllipticCurveCryptography.Point partyPublicKey) {
        EllipticCurveCryptography.Point pointSecret = ecc.add(this.privateKey, partyPublicKey);
        String secretString = digest(pointSecret.x());

        String decryptedMessage = aesDecryption(message, secretString);

        System.out.printf("Hello! %s speaking here. I just received the following message: %s%n", this.getName(), decryptedMessage);
    }
}
