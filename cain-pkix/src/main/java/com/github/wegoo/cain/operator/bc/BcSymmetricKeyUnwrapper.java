package com.github.wegoo.cain.operator.bc;

import java.security.SecureRandom;

import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.crypto.InvalidCipherTextException;
import com.github.wegoo.cain.crypto.Wrapper;
import com.github.wegoo.cain.crypto.params.KeyParameter;
import com.github.wegoo.cain.operator.GenericKey;
import com.github.wegoo.cain.operator.OperatorException;
import com.github.wegoo.cain.operator.SymmetricKeyUnwrapper;

public class BcSymmetricKeyUnwrapper
    extends SymmetricKeyUnwrapper
{
    private SecureRandom random;
    private Wrapper wrapper;
    private KeyParameter wrappingKey;

    public BcSymmetricKeyUnwrapper(AlgorithmIdentifier wrappingAlgorithm, Wrapper wrapper, KeyParameter wrappingKey)
    {
        super(wrappingAlgorithm);

        this.wrapper = wrapper;
        this.wrappingKey = wrappingKey;
    }

    public BcSymmetricKeyUnwrapper setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException
    {
        wrapper.init(false, wrappingKey);

        try
        {
            return new GenericKey(encryptedKeyAlgorithm, wrapper.unwrap(encryptedKey, 0, encryptedKey.length));
        }
        catch (InvalidCipherTextException e)
        {
            throw new OperatorException("unable to unwrap key: " + e.getMessage(), e);
        }
    }
}
