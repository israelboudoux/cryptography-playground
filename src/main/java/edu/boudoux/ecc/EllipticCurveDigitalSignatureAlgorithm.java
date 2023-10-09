package edu.boudoux.ecc;

/**
 * ECDSA
 */
public class EllipticCurveDigitalSignatureAlgorithm {
    /**
     * domain parameters: a, b, G, p, Y, n (n is a prime s.t. n * G = O)
     * Signing:
     *  select a random x s.t. 1 <= x < n (private key)
     *  calculate public key: Y = x * G
     *  Generate a one-time value 'k' s.t. 0 < k < n (should be used only once)
     *  hash the message: H = hash(M)
     *  r = (k * G)_x mod n (_x means to pick the x coordinate)
     *  s = k^-1 * (H + x.r) mod n
     *  (r, s) is the signature!
     */
    public String sign(String message) {
        return null;
    }

    /**
     * Verifying:
     *  hash the message: H = hash(M)
     *  w = s^-1 mod n
     *  u_1 = H * w mod n
     *  u_2 = r * w mod n
     *  (x, y) = u_1 * G + u_2 * Y
     *  if r === x mod n; signature is valid
     */
    public boolean verify(String message) {
        return false;
    }
}
