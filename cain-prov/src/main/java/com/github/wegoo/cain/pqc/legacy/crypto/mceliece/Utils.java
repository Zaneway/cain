package com.github.wegoo.cain.pqc.legacy.crypto.mceliece;

import com.github.wegoo.cain.crypto.Digest;
import com.github.wegoo.cain.crypto.digests.SHA1Digest;
import com.github.wegoo.cain.crypto.digests.SHA224Digest;
import com.github.wegoo.cain.crypto.digests.SHA256Digest;
import com.github.wegoo.cain.crypto.digests.SHA384Digest;
import com.github.wegoo.cain.crypto.digests.SHA512Digest;

class Utils
{
    static Digest getDigest(String digestName)
    {
        if (digestName.equals("SHA-1"))
        {
            return new SHA1Digest();
        }
        if (digestName.equals("SHA-224"))
        {
            return new SHA224Digest();
        }
        if (digestName.equals("SHA-256"))
        {
            return new SHA256Digest();
        }
        if (digestName.equals("SHA-384"))
        {
            return new SHA384Digest();
        }
        if (digestName.equals("SHA-512"))
        {
            return new SHA512Digest();
        }

        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
    }
}
