package com.github.wegoo.cain.pqc.crypto.ntru;

import com.github.wegoo.cain.util.Arrays;

/**
 * NTRU public key parameter class.
 */
public class NTRUPublicKeyParameters
    extends NTRUKeyParameters
{
    final byte[] publicKey;

    public NTRUPublicKeyParameters(NTRUParameters params, byte[] key)
    {
        super(false, params);
        this.publicKey = Arrays.clone(key);
    }

    /**
     * Get public key.
     *
     * @return a byte array containing public key
     */
    public byte[] getPublicKey()
    {
        return Arrays.clone(this.publicKey);
    }

    /**
     * Get the encoding of public key.
     *
     * @return a byte array containing public key encoding
     */
    public byte[] getEncoded()
    {
        return getPublicKey();
    }
}
