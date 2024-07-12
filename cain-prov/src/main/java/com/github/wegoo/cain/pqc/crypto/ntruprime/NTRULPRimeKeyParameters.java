package com.github.wegoo.cain.pqc.crypto.ntruprime;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public class NTRULPRimeKeyParameters
    extends AsymmetricKeyParameter
{
    private final NTRULPRimeParameters params;

    public NTRULPRimeKeyParameters(boolean privateKey, NTRULPRimeParameters params)
    {
        super(privateKey);
        this.params = params;
    }

    public NTRULPRimeParameters getParameters()
    {
        return params;
    }
}
