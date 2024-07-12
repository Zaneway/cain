package com.github.wegoo.cain.its;

import com.github.wegoo.cain.oer.its.ieee1609dot2.EncryptedDataEncryptionKey;

public interface ETSIKeyWrapper
{
    EncryptedDataEncryptionKey wrap(byte[] secretKey);
}
