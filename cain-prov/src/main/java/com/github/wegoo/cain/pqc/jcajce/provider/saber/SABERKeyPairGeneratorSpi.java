package com.github.wegoo.cain.pqc.jcajce.provider.saber;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.pqc.crypto.saber.SABERKeyGenerationParameters;
import com.github.wegoo.cain.pqc.crypto.saber.SABERKeyPairGenerator;
import com.github.wegoo.cain.pqc.crypto.saber.SABERParameters;
import com.github.wegoo.cain.pqc.crypto.saber.SABERPrivateKeyParameters;
import com.github.wegoo.cain.pqc.crypto.saber.SABERPublicKeyParameters;
import com.github.wegoo.cain.pqc.jcajce.provider.util.SpecUtil;
import com.github.wegoo.cain.pqc.jcajce.spec.SABERParameterSpec;
import com.github.wegoo.cain.util.Strings;

public class SABERKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(SABERParameterSpec.lightsaberkem128r3.getName(), SABERParameters.lightsaberkem128r3);
        parameters.put(SABERParameterSpec.saberkem128r3.getName(), SABERParameters.saberkem128r3);
        parameters.put(SABERParameterSpec.firesaberkem128r3.getName(), SABERParameters.firesaberkem128r3);
        parameters.put(SABERParameterSpec.lightsaberkem192r3.getName(), SABERParameters.lightsaberkem192r3);
        parameters.put(SABERParameterSpec.saberkem192r3.getName(), SABERParameters.saberkem192r3);
        parameters.put(SABERParameterSpec.firesaberkem192r3.getName(), SABERParameters.firesaberkem192r3);
        parameters.put(SABERParameterSpec.lightsaberkem256r3.getName(), SABERParameters.lightsaberkem256r3);
        parameters.put(SABERParameterSpec.saberkem256r3.getName(), SABERParameters.saberkem256r3);
        parameters.put(SABERParameterSpec.firesaberkem256r3.getName(), SABERParameters.firesaberkem256r3);
    }

    SABERKeyGenerationParameters param;
    SABERKeyPairGenerator engine = new SABERKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public SABERKeyPairGeneratorSpi()
    {
        super("SABER");
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
        String name = getNameFromParams(params);

        if (name != null)
        {
            param = new SABERKeyGenerationParameters(random, (SABERParameters)parameters.get(name));

            engine.init(param);
            initialised = true;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + params);
        }
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof SABERParameterSpec)
        {
            SABERParameterSpec saberParams = (SABERParameterSpec)paramSpec;
            return saberParams.getName();
        }
        else
        {
            return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new SABERKeyGenerationParameters(random, SABERParameters.firesaberkem256r3);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SABERPublicKeyParameters pub = (SABERPublicKeyParameters)pair.getPublic();
        SABERPrivateKeyParameters priv = (SABERPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSABERPublicKey(pub), new BCSABERPrivateKey(priv));
    }
}