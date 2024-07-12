package com.github.wegoo.cain.crypto.modes;

import com.github.wegoo.cain.crypto.BlockCipher;
import com.github.wegoo.cain.crypto.MultiBlockCipher;
import com.github.wegoo.cain.crypto.SkippingStreamCipher;

public interface CTRModeCipher
    extends MultiBlockCipher, SkippingStreamCipher
{
    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    BlockCipher getUnderlyingCipher();
}
