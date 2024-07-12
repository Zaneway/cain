package com.github.wegoo.cain.pqc.crypto.sphincsplus;

interface SPHINCSPlusEngineProvider
{
    int getN();

    SPHINCSPlusEngine get();
}
