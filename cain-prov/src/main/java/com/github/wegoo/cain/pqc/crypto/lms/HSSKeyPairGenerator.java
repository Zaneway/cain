package com.github.wegoo.cain.pqc.crypto.lms;

import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class HSSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    HSSKeyGenerationParameters param;

    public void init(KeyGenerationParameters param)
    {
        this.param = (HSSKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        HSSPrivateKeyParameters privKey = HSS.generateHSSKeyPair(param);

        return new AsymmetricCipherKeyPair(privKey.getPublicKey(), privKey);
    }
}
