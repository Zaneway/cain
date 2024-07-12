package com.github.wegoo.cain.crypto.prng;

import com.github.wegoo.cain.crypto.prng.drbg.SP80090DRBG;

interface DRBGProvider
{
    String getAlgorithm();

    SP80090DRBG get(EntropySource entropySource);
}
