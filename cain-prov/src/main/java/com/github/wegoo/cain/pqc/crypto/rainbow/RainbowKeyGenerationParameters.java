package com.github.wegoo.cain.pqc.crypto.rainbow;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class RainbowKeyGenerationParameters
    extends KeyGenerationParameters
{
    private RainbowParameters params;

    public RainbowKeyGenerationParameters(
        SecureRandom random,
        RainbowParameters params
    )
    {

        // TODO: actual strength
        super(random, 256);
        this.params = params;
    }

    public RainbowParameters getParameters()
    {
        return params;
    }
}

