package com.github.wegoo.cain.pqc.crypto.saber;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public class SABERKeyParameters
    extends AsymmetricKeyParameter
{
    private SABERParameters params;
    public SABERKeyParameters(
            boolean isPrivate,
            SABERParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public SABERParameters getParameters()
    {
        return params;
    }
}
