package com.github.wegoo.cain.crypto;

import java.io.IOException;
import java.io.InputStream;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public interface KeyParser
{
    AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException;
}
