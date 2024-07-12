package com.github.wegoo.cain.pkcs.bc;

import java.io.InputStream;

import com.github.wegoo.cain.asn1.pkcs.PKCS12PBEParams;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.crypto.ExtendedDigest;
import com.github.wegoo.cain.crypto.digests.SHA1Digest;
import com.github.wegoo.cain.crypto.generators.PKCS12ParametersGenerator;
import com.github.wegoo.cain.crypto.io.CipherInputStream;
import com.github.wegoo.cain.crypto.paddings.PaddedBufferedBlockCipher;
import com.github.wegoo.cain.operator.GenericKey;
import com.github.wegoo.cain.operator.InputDecryptor;
import com.github.wegoo.cain.operator.InputDecryptorProvider;

public class BcPKCS12PBEInputDecryptorProviderBuilder
{
    private ExtendedDigest digest;

    public BcPKCS12PBEInputDecryptorProviderBuilder()
    {
         this(new SHA1Digest());
    }

    public BcPKCS12PBEInputDecryptorProviderBuilder(ExtendedDigest digest)
    {
         this.digest = digest;
    }

    public InputDecryptorProvider build(final char[] password)
    {
        return new InputDecryptorProvider()
        {
            public InputDecryptor get(final AlgorithmIdentifier algorithmIdentifier)
            {
                final PaddedBufferedBlockCipher engine = PKCS12PBEUtils.getEngine(algorithmIdentifier.getAlgorithm());

                PKCS12PBEParams           pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

                CipherParameters params = PKCS12PBEUtils.createCipherParameters(algorithmIdentifier.getAlgorithm(), digest, engine.getBlockSize(), pbeParams, password);

                engine.init(false, params);

                return new InputDecryptor()
                {
                    public AlgorithmIdentifier getAlgorithmIdentifier()
                    {
                        return algorithmIdentifier;
                    }

                    public InputStream getInputStream(InputStream input)
                    {
                        return new CipherInputStream(input, engine);
                    }

                    public GenericKey getKey()
                    {
                        return new GenericKey(algorithmIdentifier, PKCS12ParametersGenerator.PKCS12PasswordToBytes(password));
                    }
                };
            }
        };

    }
}
