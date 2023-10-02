package edu.boudoux.dhke;

import edu.boudoux.utils.CryptographyUtils;
import org.apache.commons.lang3.tuple.Pair;
import java.math.BigInteger;

public class DiffieHellmanKeyExchange {

    /**
     * Performs the setup which is the phase where a prime number is generated and a primitive element in the set Zp*
     * is picked up
     *
     * @return a pair consisting of a prime number (L) and the generator (R) in the set.
     */
    public Pair<BigInteger, BigInteger> setup(int totalBits) {
        final BigInteger p = CryptographyUtils.generatePrime(totalBits);

        final BigInteger generator = CryptographyUtils.getGenerator(p);

        return Pair.of(p, generator);
    }

    /**
     * Generates the private key in the range {2, ..., p - 2}
     *
     * @param p
     * @return
     */
    public BigInteger generatePrivateKey(BigInteger p) {
        return CryptographyUtils.generateNumber(BigInteger.TWO, p.subtract(BigInteger.ONE));
    }
}
