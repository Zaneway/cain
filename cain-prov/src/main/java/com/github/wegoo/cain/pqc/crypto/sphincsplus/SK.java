package com.github.wegoo.cain.pqc.crypto.sphincsplus;

class SK
{
    final byte[] seed;
    final byte[] prf;

    SK(byte[] seed, byte[] prf)
    {
        this.seed = seed;
        this.prf = prf;
    }
}
