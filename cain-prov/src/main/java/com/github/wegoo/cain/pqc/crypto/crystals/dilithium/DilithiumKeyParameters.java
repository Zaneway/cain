package com.github.wegoo.cain.pqc.crypto.crystals.dilithium;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public class DilithiumKeyParameters
    extends AsymmetricKeyParameter
{
    private final DilithiumParameters params;

    public DilithiumKeyParameters(
        boolean isPrivate,
        DilithiumParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public DilithiumParameters getParameters()
    {
        return params;
    }

}
