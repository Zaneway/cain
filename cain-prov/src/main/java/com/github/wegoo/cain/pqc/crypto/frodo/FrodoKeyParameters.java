package com.github.wegoo.cain.pqc.crypto.frodo;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public class FrodoKeyParameters
        extends AsymmetricKeyParameter
{
    private FrodoParameters params;

    public FrodoKeyParameters(
        boolean isPrivate,
        FrodoParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public FrodoParameters getParameters()
    {
        return params;
    }

}
