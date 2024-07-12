package com.github.wegoo.cain.pqc.crypto.xwing;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.wegoo.cain.crypto.KeyGenerationParameters;
import com.github.wegoo.cain.crypto.generators.X25519KeyPairGenerator;
import com.github.wegoo.cain.crypto.params.X25519KeyGenerationParameters;
import com.github.wegoo.cain.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import com.github.wegoo.cain.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import com.github.wegoo.cain.pqc.crypto.crystals.kyber.KyberParameters;

public class XWingKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    private void initialize(
        KeyGenerationParameters param)
    {
        this.random = param.getRandom();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        KyberKeyPairGenerator kyberKeyGen = new KyberKeyPairGenerator();

        kyberKeyGen.init(new KyberKeyGenerationParameters(random, KyberParameters.kyber768));

        X25519KeyPairGenerator x25519KeyGen = new X25519KeyPairGenerator();

        x25519KeyGen.init(new X25519KeyGenerationParameters(random));

        AsymmetricCipherKeyPair kybKp = kyberKeyGen.generateKeyPair();
        AsymmetricCipherKeyPair xdhKp = x25519KeyGen.generateKeyPair();

        return new AsymmetricCipherKeyPair(
            new XWingPublicKeyParameters(kybKp.getPublic(), xdhKp.getPublic()),
            new XWingPrivateKeyParameters(kybKp.getPrivate(), xdhKp.getPrivate()));
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }

}
