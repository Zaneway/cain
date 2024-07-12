package com.github.wegoo.cain.pqc.crypto.picnic;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class PicnicKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final PicnicParameters parameters;

    public PicnicKeyGenerationParameters(SecureRandom random, PicnicParameters parameters)
    {
        super(random, -1);
        this.parameters = parameters;
    }

    public PicnicParameters getParameters()
    {
        return parameters;
    }
}
