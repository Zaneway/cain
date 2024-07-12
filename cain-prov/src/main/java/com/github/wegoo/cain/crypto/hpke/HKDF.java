package com.github.wegoo.cain.crypto.hpke;

import com.github.wegoo.cain.crypto.Digest;
import com.github.wegoo.cain.crypto.digests.SHA256Digest;
import com.github.wegoo.cain.crypto.digests.SHA384Digest;
import com.github.wegoo.cain.crypto.digests.SHA512Digest;
import com.github.wegoo.cain.crypto.generators.HKDFBytesGenerator;
import com.github.wegoo.cain.crypto.params.HKDFParameters;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Pack;

class HKDF
{
    private final static String versionLabel = "HPKE-v1";
    private final HKDFBytesGenerator kdf;
    private final int hashLength;

    HKDF(short kdfId)
    {
        Digest hash;

        switch (kdfId)
        {
        case HPKE.kdf_HKDF_SHA256:
            hash = new SHA256Digest();
            break;
        case HPKE.kdf_HKDF_SHA384:
            hash = new SHA384Digest();
            break;
        case HPKE.kdf_HKDF_SHA512:
            hash = new SHA512Digest();
            break;
        default:
            throw new IllegalArgumentException("invalid kdf id");
        }
        kdf = new HKDFBytesGenerator(hash);
        hashLength = hash.getDigestSize();
    }

    int getHashSize()
    {
        return hashLength;
    }
    
    // todo remove suiteID
    protected byte[] LabeledExtract(byte[] salt, byte[] suiteID, String label, byte[] ikm)
    {
        if (salt == null)
        {
            salt = new byte[hashLength];
        }

        byte[] labeledIKM = Arrays.concatenate(versionLabel.getBytes(), suiteID, label.getBytes(), ikm);

        return kdf.extractPRK(salt, labeledIKM);
    }

    protected byte[] LabeledExpand(byte[] prk, byte[] suiteID, String label, byte[] info, int L)
    {
        if (L > (1 << 16))
        {
            throw new IllegalArgumentException("Expand length cannot be larger than 2^16");
        }
        byte[] labeledInfo = Arrays.concatenate(Pack.shortToBigEndian((short)L), versionLabel.getBytes(), suiteID, label.getBytes());

        kdf.init(HKDFParameters.skipExtractParameters(prk, Arrays.concatenate(labeledInfo, info)));

        byte[] rv = new byte[L];

        kdf.generateBytes(rv, 0, rv.length);

        return rv;
    }

    protected byte[] Extract(byte[] salt, byte[] ikm)
    {
        if (salt == null)
        {
            salt = new byte[hashLength];
        }

        return kdf.extractPRK(salt, ikm);
    }

    protected byte[] Expand(byte[] prk, byte[] info, int L)
    {
        if (L > (1 << 16))
        {
            throw new IllegalArgumentException("Expand length cannot be larger than 2^16");
        }

        kdf.init(HKDFParameters.skipExtractParameters(prk, info));

        byte[] rv = new byte[L];

        kdf.generateBytes(rv, 0, rv.length);

        return rv;
    }
}
