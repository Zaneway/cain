package com.github.wegoo.cain.pqc.crypto.hqc;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class HQCKeyGenerationParameters
    extends KeyGenerationParameters
{
    private HQCParameters params;

    public HQCKeyGenerationParameters(
        SecureRandom random,
        HQCParameters params)
    {
        super(random, 256);
        this.params = params;
    }

    public HQCParameters getParameters()
    {
        return params;
    }
}
