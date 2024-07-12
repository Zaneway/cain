package com.github.wegoo.cain.pqc.jcajce.provider.saber;

import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.pqc.crypto.saber.SABERPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PublicKeyFactory;
import com.github.wegoo.cain.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.SABERKey;
import com.github.wegoo.cain.pqc.jcajce.spec.SABERParameterSpec;
import com.github.wegoo.cain.util.Arrays;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class BCSABERPublicKey
        implements PublicKey, SABERKey
{
    private static final long serialVersionUID = 1L;

    private transient SABERPublicKeyParameters params;

    public BCSABERPublicKey(
            SABERPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCSABERPublicKey(SubjectPublicKeyInfo keyInfo)
            throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
            throws IOException
    {
        this.params = (SABERPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this SABER public key with another object.
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

        if (o instanceof BCSABERPublicKey)
        {
            BCSABERPublicKey otherKey = (BCSABERPublicKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "SABER"
     */
    public final String getAlgorithm()
    {
        return "SABER";
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "X.509";
    }

    public SABERParameterSpec getParameterSpec()
    {
        return SABERParameterSpec.fromName(params.getParameters().getName());
    }

    SABERPublicKeyParameters getKeyParams()
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
