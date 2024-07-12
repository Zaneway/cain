package com.github.wegoo.cain.pqc.crypto.bike;

import com.github.wegoo.cain.util.Arrays;

public class BIKEPublicKeyParameters
    extends BIKEKeyParameters
{
    byte[] publicKey;

    /**
     * Constructor.
     *
     * @param publicKey byte
     */
    public BIKEPublicKeyParameters(BIKEParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(publicKey);
    }
}
