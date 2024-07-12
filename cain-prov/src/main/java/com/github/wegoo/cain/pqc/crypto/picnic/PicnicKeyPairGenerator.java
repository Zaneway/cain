package com.github.wegoo.cain.pqc.crypto.picnic;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class PicnicKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator

{
    private SecureRandom random;
    private PicnicParameters parameters;

    public void init(KeyGenerationParameters param)
    {
        random = param.getRandom();
        parameters = ((PicnicKeyGenerationParameters) param).getParameters();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        PicnicEngine engine = parameters.getEngine();
        byte[] sk = new byte[engine.getSecretKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.crypto_sign_keypair(pk, sk, random);

        PicnicPublicKeyParameters pubKey = new PicnicPublicKeyParameters(parameters, pk);
        PicnicPrivateKeyParameters privKey = new PicnicPrivateKeyParameters(parameters, sk);


        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }
}
