package com.github.wegoo.cain.pqc.crypto.gemss;

import com.github.wegoo.cain.util.Arrays;

public class GeMSSPublicKeyParameters
    extends GeMSSKeyParameters
{
    private final byte[] pk;

    public GeMSSPublicKeyParameters(GeMSSParameters parameters, byte[] pkValues)
    {
        super(false, parameters);
        pk = new byte[pkValues.length];
        System.arraycopy(pkValues, 0, pk, 0, pk.length);
    }

    public byte[] getPK()
    {
        return pk;
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(pk);
    }
}
