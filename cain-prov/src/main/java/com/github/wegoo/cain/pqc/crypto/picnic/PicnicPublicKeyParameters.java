package com.github.wegoo.cain.pqc.crypto.picnic;

import com.github.wegoo.cain.util.Arrays;

public class PicnicPublicKeyParameters
    extends PicnicKeyParameters
{

    private  final byte[] publicKey;

//    public picnicPublicKeyParameters(picnicParameters parameters, byte[] ptEncoded, byte[] ctEncoded)
    public PicnicPublicKeyParameters(PicnicParameters parameters, byte[] pkEncoded)
    {
        super(false, parameters);
        publicKey = Arrays.clone(pkEncoded);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(publicKey);
    }

}
