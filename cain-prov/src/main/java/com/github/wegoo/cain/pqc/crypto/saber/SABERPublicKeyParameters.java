package com.github.wegoo.cain.pqc.crypto.saber;

import com.github.wegoo.cain.util.Arrays;

public class SABERPublicKeyParameters
    extends SABERKeyParameters
{
    private final byte[] publicKey;

    public SABERPublicKeyParameters(SABERParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }
}
