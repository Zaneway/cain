package com.github.wegoo.cain.pqc.jcajce.provider.sphincs;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.nist.NISTObjectIdentifiers;
import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.crypto.digests.SHA3Digest;
import com.github.wegoo.cain.crypto.digests.SHA512tDigest;
import com.github.wegoo.cain.pqc.crypto.sphincs.SPHINCS256KeyGenerationParameters;
import com.github.wegoo.cain.pqc.crypto.sphincs.SPHINCS256KeyPairGenerator;
import com.github.wegoo.cain.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import com.github.wegoo.cain.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import com.github.wegoo.cain.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;

public class Sphincs256KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    ASN1ObjectIdentifier treeDigest = NISTObjectIdentifiers.id_sha512_256;

    SPHINCS256KeyGenerationParameters param;
    SPHINCS256KeyPairGenerator engine = new SPHINCS256KeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public Sphincs256KeyPairGeneratorSpi()
    {
        super("SPHINCS256");
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
        if (!(params instanceof SPHINCS256KeyGenParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a SPHINCS256KeyGenParameterSpec");
        }

        SPHINCS256KeyGenParameterSpec sphincsParams = (SPHINCS256KeyGenParameterSpec)params;

        if (sphincsParams.getTreeDigest().equals(SPHINCS256KeyGenParameterSpec.SHA512_256))
        {
            treeDigest = NISTObjectIdentifiers.id_sha512_256;
            param = new SPHINCS256KeyGenerationParameters(random, new SHA512tDigest(256));
        }
        else if (sphincsParams.getTreeDigest().equals(SPHINCS256KeyGenParameterSpec.SHA3_256))
        {
            treeDigest = NISTObjectIdentifiers.id_sha3_256;
            param = new SPHINCS256KeyGenerationParameters(random, new SHA3Digest(256));
        }

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new SPHINCS256KeyGenerationParameters(random, new SHA512tDigest(256));

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SPHINCSPublicKeyParameters pub = (SPHINCSPublicKeyParameters)pair.getPublic();
        SPHINCSPrivateKeyParameters priv = (SPHINCSPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSphincs256PublicKey(treeDigest, pub), new BCSphincs256PrivateKey(treeDigest, priv));
    }
}
