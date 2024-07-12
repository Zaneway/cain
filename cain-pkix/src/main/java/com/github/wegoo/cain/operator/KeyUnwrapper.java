package com.github.wegoo.cain.operator;

import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;

public interface KeyUnwrapper
{
    AlgorithmIdentifier getAlgorithmIdentifier();

    GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptionKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException;
}
