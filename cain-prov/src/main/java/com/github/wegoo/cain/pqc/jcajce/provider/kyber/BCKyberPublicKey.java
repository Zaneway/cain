package com.github.wegoo.cain.pqc.jcajce.provider.kyber;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PublicKeyFactory;
import com.github.wegoo.cain.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.KyberPublicKey;
import com.github.wegoo.cain.pqc.jcajce.provider.util.KeyUtil;
import com.github.wegoo.cain.pqc.jcajce.spec.KyberParameterSpec;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Strings;

public class BCKyberPublicKey
    implements KyberPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient KyberPublicKeyParameters params;
    private transient String algorithm;
    private transient byte[] encoding;

    public BCKyberPublicKey(
        KyberPublicKeyParameters params)
    {
        init(params);
    }

    public BCKyberPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init((KyberPublicKeyParameters)PublicKeyFactory.createKey(keyInfo));
    }

    private void init(KyberPublicKeyParameters params)
    {
        this.params = params;
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    /**
     * Compare this Kyber public key with another object.
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

        if (o instanceof BCKyberPublicKey)
        {
            BCKyberPublicKey otherKey = (BCKyberPublicKey)o;

            return Arrays.areEqual(this.getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    /**
     * @return name of the algorithm - "KYBER512, KYBER768, etc..."
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

    public KyberParameterSpec getParameterSpec()
    {
        return KyberParameterSpec.fromName(params.getParameters().getName());
    }

    KyberPublicKeyParameters getKeyParams()
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
