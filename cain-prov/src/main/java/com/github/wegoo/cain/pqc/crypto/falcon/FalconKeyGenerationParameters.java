package com.github.wegoo.cain.pqc.crypto.falcon;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class FalconKeyGenerationParameters
    extends KeyGenerationParameters
{

    private final FalconParameters params;

    public FalconKeyGenerationParameters(SecureRandom random, FalconParameters parameters)
    {
        super(random, 320);
        this.params = parameters;
    }

    public FalconParameters getParameters()
    {
        return this.params;
    }
}
