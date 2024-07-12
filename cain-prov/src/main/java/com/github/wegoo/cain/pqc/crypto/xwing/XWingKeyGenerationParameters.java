package com.github.wegoo.cain.pqc.crypto.xwing;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class XWingKeyGenerationParameters
    extends KeyGenerationParameters
{
    public XWingKeyGenerationParameters(SecureRandom random)
    {
        super(random, 128);
    }
}
