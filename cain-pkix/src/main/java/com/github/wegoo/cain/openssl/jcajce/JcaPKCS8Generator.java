package com.github.wegoo.cain.openssl.jcajce;

import java.security.PrivateKey;

import com.github.wegoo.cain.asn1.pkcs.PrivateKeyInfo;
import com.github.wegoo.cain.openssl.PKCS8Generator;
import com.github.wegoo.cain.operator.OutputEncryptor;
import com.github.wegoo.cain.util.io.pem.PemGenerationException;

public class JcaPKCS8Generator
    extends PKCS8Generator
{
    public JcaPKCS8Generator(PrivateKey key, OutputEncryptor encryptor)
         throws PemGenerationException
    {
         super(PrivateKeyInfo.getInstance(key.getEncoded()), encryptor);
    }
}
