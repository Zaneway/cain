package com.github.wegoo.cain.pqc.jcajce.provider.rainbow;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PublicKeyFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.RainbowPublicKey;
import com.github.wegoo.cain.pqc.jcajce.provider.util.KeyUtil;
import com.github.wegoo.cain.pqc.jcajce.spec.RainbowParameterSpec;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Strings;
import com.github.wegoo.cain.util.encoders.Hex;

public class BCRainbowPublicKey
    implements RainbowPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient RainbowPublicKeyParameters params;
    private transient String algorithm;
    private transient byte[] encoding;

    public BCRainbowPublicKey(
        RainbowPublicKeyParameters params)
    {
        init(params);
    }

    public BCRainbowPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init((RainbowPublicKeyParameters) PublicKeyFactory.createKey(keyInfo));
    }

    private void init(RainbowPublicKeyParameters params)
    {
        this.params = params;
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    /**
     * Compare this Rainbow public key with another object.
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

        if (o instanceof BCRainbowPublicKey)
        {
            BCRainbowPublicKey otherKey = (BCRainbowPublicKey)o;

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
            encoding = KeyUtil.getEncodedSubjectPublicKeyInfo(params);
        }

        return Arrays.clone(encoding);
    }

    public String getFormat()
    {
        return "X.509";
    }

    public RainbowParameterSpec getParameterSpec()
    {
        return RainbowParameterSpec.fromName(params.getParameters().getName());
    }

    RainbowPublicKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
