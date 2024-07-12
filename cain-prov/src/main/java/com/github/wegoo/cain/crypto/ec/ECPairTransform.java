package com.github.wegoo.cain.crypto.ec;

import com.github.wegoo.cain.crypto.CipherParameters;

public interface ECPairTransform
{
    void init(CipherParameters params);

    ECPair transform(ECPair cipherText);
}
