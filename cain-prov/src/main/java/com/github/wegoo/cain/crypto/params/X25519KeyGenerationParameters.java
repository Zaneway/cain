package com.github.wegoo.cain.crypto.params;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class X25519KeyGenerationParameters
    extends KeyGenerationParameters
{
    public X25519KeyGenerationParameters(SecureRandom random)
    {
        super(random, 255);
    }
}
