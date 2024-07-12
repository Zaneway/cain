package com.github.wegoo.cain.pqc.crypto.bike;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.EncapsulatedSecretGenerator;
import com.github.wegoo.cain.crypto.SecretWithEncapsulation;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.pqc.crypto.util.SecretWithEncapsulationImpl;
import com.github.wegoo.cain.util.Arrays;

public class BIKEKEMGenerator
    implements EncapsulatedSecretGenerator
{

    private final SecureRandom sr;

    public BIKEKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    @Override
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        BIKEPublicKeyParameters key = (BIKEPublicKeyParameters)recipientKey;
        BIKEEngine engine = key.getParameters().getEngine();

        byte[] K = new byte[key.getParameters().getLByte()];
        byte[] c0 = new byte[key.getParameters().getRByte()];
        byte[] c1 = new byte[key.getParameters().getLByte()];
        byte[] h = key.publicKey;

        engine.encaps(c0, c1, K, h, this.sr);

        byte[] cipherText = Arrays.concatenate(c0, c1);

        return new SecretWithEncapsulationImpl(Arrays.copyOfRange(K, 0, key.getParameters().getSessionKeySize() / 8), cipherText);
    }
}
