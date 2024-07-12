package com.github.wegoo.cain.crypto.params;

import com.github.wegoo.cain.crypto.DerivationParameters;

/**
 * parameters for Key derivation functions for ISO-18033
 */
public class ISO18033KDFParameters
    implements DerivationParameters
{
    byte[]  seed;

    public ISO18033KDFParameters(
        byte[]  seed)
    {
        this.seed = seed;
    }

    public byte[] getSeed()
    {
        return seed;
    }
}
