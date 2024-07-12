package com.github.wegoo.cain.its.operator;

public interface ETSIDataDecryptor
{
    byte[] decrypt(byte[] wrappedKey, byte[] content, byte[] nonce);

    /**
     * return the unwrapped key found in the data. Call after decrypt.
     *
     * @return the unwrapped key.
     */
    byte[] getKey();
}
