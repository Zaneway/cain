package com.github.wegoo.cain.crypto.ec;

import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.math.ec.ECPoint;

public interface ECDecryptor
{
    void init(CipherParameters params);

    ECPoint decrypt(ECPair cipherText);
}
