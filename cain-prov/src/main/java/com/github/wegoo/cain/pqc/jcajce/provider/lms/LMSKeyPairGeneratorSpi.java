package com.github.wegoo.cain.pqc.jcajce.provider.lms;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.crypto.KeyGenerationParameters;
import com.github.wegoo.cain.pqc.crypto.lms.HSSKeyGenerationParameters;
import com.github.wegoo.cain.pqc.crypto.lms.HSSKeyPairGenerator;
import com.github.wegoo.cain.pqc.crypto.lms.HSSPrivateKeyParameters;
import com.github.wegoo.cain.pqc.crypto.lms.HSSPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.lms.LMOtsParameters;
import com.github.wegoo.cain.pqc.crypto.lms.LMSKeyGenerationParameters;
import com.github.wegoo.cain.pqc.crypto.lms.LMSKeyPairGenerator;
import com.github.wegoo.cain.pqc.crypto.lms.LMSParameters;
import com.github.wegoo.cain.pqc.crypto.lms.LMSPrivateKeyParameters;
import com.github.wegoo.cain.pqc.crypto.lms.LMSPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.lms.LMSigParameters;
import com.github.wegoo.cain.pqc.jcajce.spec.LMSHSSKeyGenParameterSpec;
import com.github.wegoo.cain.pqc.jcajce.spec.LMSHSSParameterSpec;
import com.github.wegoo.cain.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import com.github.wegoo.cain.pqc.jcajce.spec.LMSParameterSpec;

public class LMSKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private KeyGenerationParameters param;
    private ASN1ObjectIdentifier treeDigest;
    private AsymmetricCipherKeyPairGenerator engine = new LMSKeyPairGenerator();

    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public LMSKeyPairGeneratorSpi()
    {
        super("LMS");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (params instanceof LMSKeyGenParameterSpec)
        {
            LMSKeyGenParameterSpec lmsParams = (LMSKeyGenParameterSpec)params;

            param = new LMSKeyGenerationParameters(new LMSParameters(lmsParams.getSigParams(), lmsParams.getOtsParams()), random);

            engine = new LMSKeyPairGenerator();
            engine.init(param);
        }
        else if (params instanceof LMSHSSKeyGenParameterSpec)
        {
            LMSKeyGenParameterSpec[] lmsParams = ((LMSHSSKeyGenParameterSpec)params).getLMSSpecs();
            LMSParameters[] hssParams = new LMSParameters[lmsParams.length];
            for (int i = 0; i != lmsParams.length; i++)
            {
                hssParams[i] = new LMSParameters(lmsParams[i].getSigParams(), lmsParams[i].getOtsParams());
            }
            param = new HSSKeyGenerationParameters(hssParams, random);

            engine = new HSSKeyPairGenerator();
            engine.init(param);
        }
        else if (params instanceof LMSParameterSpec)
        {
            LMSParameterSpec lmsParams = (LMSParameterSpec)params;

            param = new LMSKeyGenerationParameters(new LMSParameters(lmsParams.getSigParams(), lmsParams.getOtsParams()), random);

            engine = new LMSKeyPairGenerator();
            engine.init(param);
        }
        else if (params instanceof LMSHSSParameterSpec)
        {
            LMSParameterSpec[] lmsParams = ((LMSHSSParameterSpec)params).getLMSSpecs();
            LMSParameters[] hssParams = new LMSParameters[lmsParams.length];
            for (int i = 0; i != lmsParams.length; i++)
            {
                hssParams[i] = new LMSParameters(lmsParams[i].getSigParams(), lmsParams[i].getOtsParams());
            }
            param = new HSSKeyGenerationParameters(hssParams, random);

            engine = new HSSKeyPairGenerator();
            engine.init(param);
        }
        else
        {
            throw new InvalidAlgorithmParameterException("parameter object not a LMSParameterSpec/LMSHSSParameterSpec");
        }

        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new LMSKeyGenerationParameters(new LMSParameters(LMSigParameters.lms_sha256_n32_h10, LMOtsParameters.sha256_n32_w2), random);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();

        if (engine instanceof LMSKeyPairGenerator)
        {
            LMSPublicKeyParameters pub = (LMSPublicKeyParameters)pair.getPublic();
            LMSPrivateKeyParameters priv = (LMSPrivateKeyParameters)pair.getPrivate();

            return new KeyPair(new BCLMSPublicKey(pub), new BCLMSPrivateKey(priv));
        }
        else
        {
            HSSPublicKeyParameters pub = (HSSPublicKeyParameters)pair.getPublic();
            HSSPrivateKeyParameters priv = (HSSPrivateKeyParameters)pair.getPrivate();

            return new KeyPair(new BCLMSPublicKey(pub), new BCLMSPrivateKey(priv));
        }
    }
}
