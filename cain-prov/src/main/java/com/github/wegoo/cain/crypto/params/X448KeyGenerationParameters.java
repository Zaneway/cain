package com.github.wegoo.cain.crypto.params;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class X448KeyGenerationParameters
    extends KeyGenerationParameters
{
    public X448KeyGenerationParameters(SecureRandom random)
    {
        super(random, 448);
    }
}
