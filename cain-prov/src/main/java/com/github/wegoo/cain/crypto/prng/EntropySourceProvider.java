package com.github.wegoo.cain.crypto.prng;

public interface EntropySourceProvider
{
    EntropySource get(final int bitsRequired);
}
