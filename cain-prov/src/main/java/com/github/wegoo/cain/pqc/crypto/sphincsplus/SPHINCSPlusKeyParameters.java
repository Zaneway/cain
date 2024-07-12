package com.github.wegoo.cain.pqc.crypto.sphincsplus;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public class SPHINCSPlusKeyParameters
    extends AsymmetricKeyParameter
{
    final SPHINCSPlusParameters parameters;

    protected SPHINCSPlusKeyParameters(boolean isPrivate, SPHINCSPlusParameters parameters)
    {
        super(isPrivate);
        this.parameters = parameters;
    }

    public SPHINCSPlusParameters getParameters()
    {
        return parameters;
    }
}
