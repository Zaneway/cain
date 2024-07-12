package com.github.wegoo.cain.pqc.crypto.cmce;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class CMCEKeyGenerationParameters
    extends KeyGenerationParameters
{
    private CMCEParameters params;

    public CMCEKeyGenerationParameters(
        SecureRandom random,
        CMCEParameters cmceParams)
    {
        super(random, 256);
        this.params = cmceParams;
    }

    public CMCEParameters getParameters()
    {
        return params;
    }
}
