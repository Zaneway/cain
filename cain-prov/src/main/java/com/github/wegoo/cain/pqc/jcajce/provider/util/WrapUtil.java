package com.github.wegoo.cain.pqc.jcajce.provider.util;

import java.security.InvalidKeyException;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.nist.NISTObjectIdentifiers;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.asn1.x9.X9ObjectIdentifiers;
import com.github.wegoo.cain.crypto.DerivationFunction;
import com.github.wegoo.cain.crypto.Digest;
import com.github.wegoo.cain.crypto.Wrapper;
import com.github.wegoo.cain.crypto.Xof;
import com.github.wegoo.cain.crypto.agreement.kdf.ConcatenationKDFGenerator;
import com.github.wegoo.cain.crypto.digests.SHA256Digest;
import com.github.wegoo.cain.crypto.digests.SHA512Digest;
import com.github.wegoo.cain.crypto.digests.SHAKEDigest;
import com.github.wegoo.cain.crypto.engines.AESEngine;
import com.github.wegoo.cain.crypto.engines.ARIAEngine;
import com.github.wegoo.cain.crypto.engines.CamelliaEngine;
import com.github.wegoo.cain.crypto.engines.RFC3394WrapEngine;
import com.github.wegoo.cain.crypto.engines.RFC5649WrapEngine;
import com.github.wegoo.cain.crypto.engines.SEEDEngine;
import com.github.wegoo.cain.crypto.generators.KDF2BytesGenerator;
import com.github.wegoo.cain.crypto.params.KDFParameters;
import com.github.wegoo.cain.crypto.params.KeyParameter;
import com.github.wegoo.cain.jcajce.spec.KTSParameterSpec;
import com.github.wegoo.cain.util.Arrays;

public class WrapUtil
{
    public static Wrapper getKeyWrapper(KTSParameterSpec ktsParameterSpec, byte[] secret)
        throws InvalidKeyException
    {
        Wrapper kWrap = getWrapper(ktsParameterSpec.getKeyAlgorithmName());

        AlgorithmIdentifier kdfAlgorithm = ktsParameterSpec.getKdfAlgorithm();
        if (kdfAlgorithm == null)
        {
            kWrap.init(true, new KeyParameter(Arrays.copyOfRange(secret, 0, (ktsParameterSpec.getKeySize() + 7) / 8)));
        }
        else
        {
            kWrap.init(true, new KeyParameter(makeKeyBytes(ktsParameterSpec, secret)));
        }

        return kWrap;
    }

    public static Wrapper getKeyUnwrapper(KTSParameterSpec ktsParameterSpec, byte[] secret)
        throws InvalidKeyException
    {
        Wrapper kWrap = getWrapper(ktsParameterSpec.getKeyAlgorithmName());

        AlgorithmIdentifier kdfAlgorithm = ktsParameterSpec.getKdfAlgorithm();
        if (kdfAlgorithm == null)
        {
            kWrap.init(false, new KeyParameter(secret, 0, (ktsParameterSpec.getKeySize()+ 7) / 8));
        }
        else
        {
            kWrap.init(false, new KeyParameter(makeKeyBytes(ktsParameterSpec, secret)));
        }

        return kWrap;
    }

    public static Wrapper getWrapper(String keyAlgorithmName)
    {
        Wrapper kWrap;

        if (keyAlgorithmName.equalsIgnoreCase("AESWRAP") || keyAlgorithmName.equalsIgnoreCase("AES"))
        {
            kWrap = new RFC3394WrapEngine(new AESEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("ARIA"))
        {
            kWrap = new RFC3394WrapEngine(new ARIAEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("Camellia"))
        {
            kWrap = new RFC3394WrapEngine(new CamelliaEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("SEED"))
        {
            kWrap = new RFC3394WrapEngine(new SEEDEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("AES-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new AESEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("Camellia-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new CamelliaEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("ARIA-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new ARIAEngine());
        }
        else
        {
            throw new UnsupportedOperationException("unknown key algorithm: " + keyAlgorithmName);
        }
        return kWrap;
    }

    private static byte[] makeKeyBytes(KTSParameterSpec ktsSpec, byte[] secret)
        throws InvalidKeyException
    {
        AlgorithmIdentifier kdfAlgorithm = ktsSpec.getKdfAlgorithm();
        byte[] otherInfo = ktsSpec.getOtherInfo();
        byte[] keyBytes = new byte[(ktsSpec.getKeySize() + 7) / 8];

        if (X9ObjectIdentifiers.id_kdf_kdf2.equals(kdfAlgorithm.getAlgorithm()))
        {
            AlgorithmIdentifier digAlg = AlgorithmIdentifier.getInstance(kdfAlgorithm.getParameters());
            DerivationFunction kdf = new KDF2BytesGenerator(getDigest(digAlg.getAlgorithm()));

            kdf.init(new KDFParameters(secret, otherInfo));

            kdf.generateBytes(keyBytes, 0, keyBytes.length);
        }
        else if (X9ObjectIdentifiers.id_kdf_kdf3.equals(kdfAlgorithm.getAlgorithm()))
        {
            AlgorithmIdentifier digAlg = AlgorithmIdentifier.getInstance(kdfAlgorithm.getParameters());
            DerivationFunction kdf = new ConcatenationKDFGenerator(getDigest(digAlg.getAlgorithm()));

            kdf.init(new KDFParameters(secret, otherInfo));

            kdf.generateBytes(keyBytes, 0, keyBytes.length);
        }
        else if (NISTObjectIdentifiers.id_shake256.equals(kdfAlgorithm.getAlgorithm()))
        {
             Xof xof = new SHAKEDigest(256);

             xof.update(secret, 0, secret.length);
             xof.update(otherInfo, 0, otherInfo.length);

             xof.doFinal(keyBytes, 0, keyBytes.length);
        }
        else
        {
            throw new InvalidKeyException("Unrecognized KDF: " + kdfAlgorithm.getAlgorithm());
        }

        return keyBytes;
    }

    static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512))
        {
            return new SHA512Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake128))
        {
            return new SHAKEDigest(128);
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256))
        {
            return new SHAKEDigest(256);
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }
}
