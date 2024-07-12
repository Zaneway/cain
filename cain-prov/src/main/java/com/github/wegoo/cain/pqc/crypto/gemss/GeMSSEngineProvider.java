package com.github.wegoo.cain.pqc.crypto.gemss;

public interface GeMSSEngineProvider
{
    GeMSSEngine get();

    int getN();
}
