package com.github.wegoo.cain.operator.bc;

import com.github.wegoo.cain.crypto.engines.AESWrapEngine;
import com.github.wegoo.cain.crypto.params.KeyParameter;

public class BcAESSymmetricKeyWrapper
    extends BcSymmetricKeyWrapper
{
    public BcAESSymmetricKeyWrapper(KeyParameter wrappingKey)
    {
        super(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey);
    }
}
