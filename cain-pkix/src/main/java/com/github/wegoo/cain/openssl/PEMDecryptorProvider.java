package com.github.wegoo.cain.openssl;

import com.github.wegoo.cain.operator.OperatorCreationException;

public interface PEMDecryptorProvider
{
    PEMDecryptor get(String dekAlgName)
        throws OperatorCreationException;
}
