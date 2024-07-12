package com.github.wegoo.cain.crypto.agreement;

import java.math.BigInteger;

import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.crypto.Digest;
import com.github.wegoo.cain.crypto.params.ECDomainParameters;
import com.github.wegoo.cain.crypto.params.ECPrivateKeyParameters;
import com.github.wegoo.cain.crypto.params.ECPublicKeyParameters;
import com.github.wegoo.cain.crypto.params.ParametersWithUKM;
import com.github.wegoo.cain.math.ec.ECAlgorithms;
import com.github.wegoo.cain.math.ec.ECPoint;
import com.github.wegoo.cain.util.Arrays;

/**
 * GOST VKO key agreement class - RFC 7836 Section 4.3
 */
public class ECVKOAgreement
{
    private final Digest digest;

    private ECPrivateKeyParameters key;
    private BigInteger ukm;

    public ECVKOAgreement(Digest digest)
    {
        this.digest = digest;
    }

    public void init(CipherParameters key)
    {
        ParametersWithUKM p = (ParametersWithUKM)key;

        this.key = (ECPrivateKeyParameters)p.getParameters();
        this.ukm = new BigInteger(1, Arrays.reverse(p.getUKM()));

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("ECVKO", this.key));
    }

    public int getAgreementSize()
    {
        return digest.getDigestSize();
    }

    /**
     * @deprecated Will be removed
     */
    public int getFieldSize()
    {
        return (key.getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey)
    {
        ECPublicKeyParameters pub = (ECPublicKeyParameters)pubKey;
        ECDomainParameters params = key.getParameters();
        if (!params.equals(pub.getParameters()))
        {
            throw new IllegalStateException("ECVKO public key has wrong domain parameters");
        }

        BigInteger hd = params.getH().multiply(ukm).multiply(key.getD()).mod(params.getN());

        // Always perform calculations on the exact curve specified by our private key's parameters
        ECPoint pubPoint = ECAlgorithms.cleanPoint(params.getCurve(), pub.getQ());
        if (pubPoint.isInfinity())
        {
            throw new IllegalStateException("Infinity is not a valid public key for ECVKO");
        }

        ECPoint P = pubPoint.multiply(hd).normalize();

        if (P.isInfinity())
        {
            throw new IllegalStateException("Infinity is not a valid agreement value for ECVKO");
        }

        byte[] encoding = P.getEncoded(false);
        int encodingLength = encoding.length;
        int feSize = encodingLength / 2;

        Arrays.reverseInPlace(encoding, encodingLength - feSize * 2, feSize);
        Arrays.reverseInPlace(encoding, encodingLength - feSize    , feSize);

        byte[] rv = new byte[digest.getDigestSize()];
        digest.update(encoding, encodingLength - feSize * 2, feSize * 2);
        digest.doFinal(rv, 0);
        return rv;
    }
}
