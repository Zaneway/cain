package com.github.wegoo.cain.cms.bc;

import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.crypto.params.KeyParameter;
import com.github.wegoo.cain.operator.GenericKey;

class CMSUtils
{
    static CipherParameters getBcKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof CipherParameters)
        {
            return (CipherParameters)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new KeyParameter((byte[])key.getRepresentation());
        }

        throw new IllegalArgumentException("unknown generic key type");
    }
}
