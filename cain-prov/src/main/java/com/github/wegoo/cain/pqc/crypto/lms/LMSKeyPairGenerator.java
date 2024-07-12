package com.github.wegoo.cain.pqc.crypto.lms;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class LMSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    LMSKeyGenerationParameters param;

    public void init(KeyGenerationParameters param)
    {
        this.param = (LMSKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        SecureRandom source = param.getRandom();

        byte[] I = new byte[16];
        source.nextBytes(I);

        LMSigParameters sigParameter = param.getParameters().getLMSigParam();
        byte[] rootSecret = new byte[sigParameter.getM()];
        source.nextBytes(rootSecret);

        LMSPrivateKeyParameters privKey = LMS.generateKeys(sigParameter, param.getParameters().getLMOTSParam(), 0, I, rootSecret);

        return new AsymmetricCipherKeyPair(privKey.getPublicKey(), privKey);
    }
}
