package com.github.wegoo.cain.crypto;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public interface KeyEncoder
{
    byte[] getEncoded(AsymmetricKeyParameter keyParameter);
}
