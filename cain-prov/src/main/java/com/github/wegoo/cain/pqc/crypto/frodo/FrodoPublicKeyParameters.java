package com.github.wegoo.cain.pqc.crypto.frodo;

import com.github.wegoo.cain.util.Arrays;

public class FrodoPublicKeyParameters
    extends FrodoKeyParameters
{

    public byte[] publicKey;

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }

    public FrodoPublicKeyParameters(FrodoParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }
}
