package com.github.wegoo.cain.pqc.jcajce.provider.dilithium;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PublicKeyFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.DilithiumPublicKey;
import com.github.wegoo.cain.pqc.jcajce.provider.util.KeyUtil;
import com.github.wegoo.cain.pqc.jcajce.spec.DilithiumParameterSpec;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Strings;

public class BCDilithiumPublicKey
    implements DilithiumPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient DilithiumPublicKeyParameters params;
    private transient String algorithm;
    private transient byte[] encoding;

    public BCDilithiumPublicKey(
        DilithiumPublicKeyParameters params)
    {
        init(params);
    }

    public BCDilithiumPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init((DilithiumPublicKeyParameters) PublicKeyFactory.createKey(keyInfo));
    }

    private void init(DilithiumPublicKeyParameters params)
    {
        this.params = params;
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    /**
     * Compare this Dilithium public key with another object.
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

        if (o instanceof BCDilithiumPublicKey)
        {
            BCDilithiumPublicKey otherKey = (BCDilithiumPublicKey)o;

            return Arrays.areEqual(getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    /**
     * @return name of the algorithm - "DILITHIUM2, DILITHIUM3, etc..."
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

    public DilithiumParameterSpec getParameterSpec()
    {
        return DilithiumParameterSpec.fromName(params.getParameters().getName());
    }

    DilithiumPublicKeyParameters getKeyParams()
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
