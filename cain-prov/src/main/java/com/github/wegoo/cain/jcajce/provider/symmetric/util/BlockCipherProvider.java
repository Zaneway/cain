package com.github.wegoo.cain.jcajce.provider.symmetric.util;

import com.github.wegoo.cain.crypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}
