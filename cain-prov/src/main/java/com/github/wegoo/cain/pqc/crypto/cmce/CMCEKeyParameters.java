package com.github.wegoo.cain.pqc.crypto.cmce;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public class CMCEKeyParameters
    extends AsymmetricKeyParameter
{
    private CMCEParameters params;

    public CMCEKeyParameters(
        boolean isPrivate,
        CMCEParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public CMCEParameters getParameters()
    {
        return params;
    }

}
