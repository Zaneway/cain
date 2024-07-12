package com.github.wegoo.cain.crypto.ec;

import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.math.ec.ECPoint;

public interface ECEncryptor
{
    void init(CipherParameters params);

    ECPair encrypt(ECPoint point);
}
