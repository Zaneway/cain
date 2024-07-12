package com.github.wegoo.cain.pqc.crypto.hqc;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public class HQCKeyParameters
    extends AsymmetricKeyParameter
{
    private HQCParameters params;

    public HQCKeyParameters(
        boolean isPrivate,
        HQCParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public HQCParameters getParameters()
    {
        return params;
    }
}
