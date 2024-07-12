package com.github.wegoo.cain.pqc.crypto.saber;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

public class SABERKeyGenerationParameters
    extends KeyGenerationParameters
{
    private SABERParameters params;

    public SABERKeyGenerationParameters(
            SecureRandom random,
            SABERParameters saberParameters)
    {
        super(random, 256);
        this.params = saberParameters;
    }

    public SABERParameters getParameters()
    {
        return params;
    }
}
