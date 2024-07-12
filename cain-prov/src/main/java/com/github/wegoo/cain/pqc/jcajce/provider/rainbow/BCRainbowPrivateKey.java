package com.github.wegoo.cain.pqc.jcajce.provider.rainbow;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import com.github.wegoo.cain.asn1.ASN1Set;
import com.github.wegoo.cain.asn1.pkcs.PrivateKeyInfo;
import com.github.wegoo.cain.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import com.github.wegoo.cain.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PrivateKeyFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.RainbowPrivateKey;
import com.github.wegoo.cain.pqc.jcajce.interfaces.RainbowPublicKey;
import com.github.wegoo.cain.pqc.jcajce.provider.util.KeyUtil;
import com.github.wegoo.cain.pqc.jcajce.spec.RainbowParameterSpec;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Strings;
import com.github.wegoo.cain.util.encoders.Hex;

public class BCRainbowPrivateKey
    implements RainbowPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient RainbowPrivateKeyParameters params;
    private transient String algorithm;
    private transient byte[] encoding;
    private transient ASN1Set attributes;

    public BCRainbowPrivateKey(
        RainbowPrivateKeyParameters params)
    {
        init(params, null);
    }

    public BCRainbowPrivateKey(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init((RainbowPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo), keyInfo.getAttributes());
    }

    private void init(RainbowPrivateKeyParameters params, ASN1Set attributes)
    {
        this.attributes = attributes;
        this.params = params;
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    /**
     * Compare this Rainbow private key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCRainbowPrivateKey)
        {
            BCRainbowPrivateKey otherKey = (BCRainbowPrivateKey)o;

            return Arrays.areEqual(getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    /**
     * @return name of the algorithm
     */
    public final String getAlgorithm()
    {
        return algorithm;
    }

    public byte[] getEncoded()
    {
        if (encoding == null)
        {
            encoding = KeyUtil.getEncodedPrivateKeyInfo(params, attributes);
        }

        return Arrays.clone(encoding);
    }

    public RainbowParameterSpec getParameterSpec()
    {
        return RainbowParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public RainbowPublicKey getPublicKey()
    {
        return new BCRainbowPublicKey(new RainbowPublicKeyParameters(params.getParameters(), params.getPublicKey()));
    }

    RainbowPrivateKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
            ObjectOutputStream out)
            throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
