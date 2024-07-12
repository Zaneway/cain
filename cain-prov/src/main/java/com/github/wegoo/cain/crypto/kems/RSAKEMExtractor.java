package com.github.wegoo.cain.crypto.kems;

import java.math.BigInteger;

import com.github.wegoo.cain.crypto.CryptoServicePurpose;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.crypto.DerivationFunction;
import com.github.wegoo.cain.crypto.EncapsulatedSecretExtractor;
import com.github.wegoo.cain.crypto.constraints.ConstraintUtils;
import com.github.wegoo.cain.crypto.constraints.DefaultServiceProperties;
import com.github.wegoo.cain.crypto.params.RSAKeyParameters;

/**
 * The RSA Key Encapsulation Mechanism (RSA-KEM) from ISO 18033-2.
 */
public class RSAKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final RSAKeyParameters privKey;
    private final int keyLen;
    private DerivationFunction kdf;

    /**
     * Set up the RSA-KEM.
     *
     * @param privKey the decryption key.
     * @param keyLen length in bytes of key to generate.
     * @param kdf the key derivation function to be used.
     */
    public RSAKEMExtractor(
        RSAKeyParameters privKey,
        int keyLen,
        DerivationFunction kdf)
    {
        if (!privKey.isPrivate())
        {
            throw new IllegalArgumentException("private key required for encryption");
        }

        this.privKey = privKey;
        this.keyLen = keyLen;
        this.kdf = kdf;

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("RSAKem",
                    ConstraintUtils.bitsOfSecurityFor(this.privKey.getModulus()), privKey, CryptoServicePurpose.DECRYPTION));
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        BigInteger n = privKey.getModulus();
        BigInteger d = privKey.getExponent();

        // Decode the input
        BigInteger c = new BigInteger(1, encapsulation);

        // Decrypt the ephemeral random and encode it
        BigInteger r = c.modPow(d, n);

        return RSAKEMGenerator.generateKey(kdf, n, r, keyLen);
    }

    public int getEncapsulationLength()
    {
        return (privKey.getModulus().bitLength() + 7) / 8;
    }
}
