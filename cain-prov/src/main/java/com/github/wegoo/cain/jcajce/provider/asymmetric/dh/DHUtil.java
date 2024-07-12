package com.github.wegoo.cain.jcajce.provider.asymmetric.dh;

import java.math.BigInteger;

import com.github.wegoo.cain.crypto.params.DHParameters;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Fingerprint;
import com.github.wegoo.cain.util.Strings;

class DHUtil
{
    static String privateKeyToString(String algorithm, BigInteger x, DHParameters dhParams)
    {
        StringBuffer buf = new StringBuffer();
        String       nl = Strings.lineSeparator();

        BigInteger y = dhParams.getG().modPow(x, dhParams.getP());

        buf.append(algorithm);
        buf.append(" Private Key [").append(generateKeyFingerprint(y, dhParams)).append("]").append(nl);
        buf.append("              Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    static String publicKeyToString(String algorithm, BigInteger y, DHParameters dhParams)
    {
        StringBuffer buf = new StringBuffer();
        String       nl = Strings.lineSeparator();

        buf.append(algorithm);
        buf.append(" Public Key [").append(generateKeyFingerprint(y, dhParams)).append("]").append(nl);
        buf.append("             Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    private static String generateKeyFingerprint(BigInteger y, DHParameters dhParams)
    {
            return new Fingerprint(
                Arrays.concatenate(
                    y.toByteArray(),
                    dhParams.getP().toByteArray(), dhParams.getG().toByteArray())).toString();
    }
}
