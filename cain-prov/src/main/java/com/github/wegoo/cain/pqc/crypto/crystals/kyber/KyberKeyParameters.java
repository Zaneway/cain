package com.github.wegoo.cain.pqc.crypto.crystals.kyber;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public class KyberKeyParameters
    extends AsymmetricKeyParameter
{
    private KyberParameters params;

    public KyberKeyParameters(
        boolean isPrivate,
        KyberParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public KyberParameters getParameters()
    {
        return params;
    }

}
