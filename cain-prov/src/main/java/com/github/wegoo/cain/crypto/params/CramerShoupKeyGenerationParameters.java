package com.github.wegoo.cain.crypto.params;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class CramerShoupKeyGenerationParameters
    extends KeyGenerationParameters
{

    private CramerShoupParameters params;

    public CramerShoupKeyGenerationParameters(SecureRandom random, CramerShoupParameters params)
    {
        super(random, getStrength(params));

        this.params = params;
    }

    public CramerShoupParameters getParameters()
    {
        return params;
    }

    static int getStrength(CramerShoupParameters params)
    {
        return params.getP().bitLength();
    }
}
