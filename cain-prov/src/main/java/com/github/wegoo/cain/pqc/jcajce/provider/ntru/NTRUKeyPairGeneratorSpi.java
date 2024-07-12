package com.github.wegoo.cain.pqc.jcajce.provider.ntru;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.pqc.crypto.ntru.NTRUKeyGenerationParameters;
import com.github.wegoo.cain.pqc.crypto.ntru.NTRUKeyPairGenerator;
import com.github.wegoo.cain.pqc.crypto.ntru.NTRUParameters;
import com.github.wegoo.cain.pqc.crypto.ntru.NTRUPrivateKeyParameters;
import com.github.wegoo.cain.pqc.crypto.ntru.NTRUPublicKeyParameters;
import com.github.wegoo.cain.pqc.jcajce.provider.util.SpecUtil;
import com.github.wegoo.cain.pqc.jcajce.spec.NTRUParameterSpec;
import com.github.wegoo.cain.util.Strings;

public class NTRUKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(NTRUParameterSpec.ntruhps2048509.getName(), NTRUParameters.ntruhps2048509);
        parameters.put(NTRUParameterSpec.ntruhps2048677.getName(), NTRUParameters.ntruhps2048677);
        parameters.put(NTRUParameterSpec.ntruhps4096821.getName(), NTRUParameters.ntruhps4096821);
        parameters.put(NTRUParameterSpec.ntruhps40961229.getName(), NTRUParameters.ntruhps40961229);
        parameters.put(NTRUParameterSpec.ntruhrss701.getName(), NTRUParameters.ntruhrss701);
        parameters.put(NTRUParameterSpec.ntruhrss1373.getName(), NTRUParameters.ntruhrss1373);
    }

    NTRUKeyGenerationParameters param;
    NTRUKeyPairGenerator engine = new NTRUKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public NTRUKeyPairGeneratorSpi()
    {
        super("NTRU");
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
            param = new NTRUKeyGenerationParameters(random, (NTRUParameters)parameters.get(name));

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
        if (paramSpec instanceof NTRUParameterSpec)
        {
            NTRUParameterSpec frodoParams = (NTRUParameterSpec)paramSpec;
            return frodoParams.getName();
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
            param = new NTRUKeyGenerationParameters(random, NTRUParameters.ntruhps2048509);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        NTRUPublicKeyParameters pub = (NTRUPublicKeyParameters)pair.getPublic();
        NTRUPrivateKeyParameters priv = (NTRUPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCNTRUPublicKey(pub), new BCNTRUPrivateKey(priv));
    }
}
