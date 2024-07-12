package com.github.wegoo.cain.pqc.crypto.picnic;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public class PicnicKeyParameters
    extends AsymmetricKeyParameter
{

    final PicnicParameters parameters;

    public PicnicKeyParameters(boolean isPrivate, PicnicParameters parameters)
    {
        super(isPrivate);
        this.parameters = parameters;
    }
    public PicnicParameters getParameters()
    {
        return parameters;
    }
}
