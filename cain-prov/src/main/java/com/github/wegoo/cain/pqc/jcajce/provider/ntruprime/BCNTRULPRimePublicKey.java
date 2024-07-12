package com.github.wegoo.cain.pqc.jcajce.provider.ntruprime;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PublicKeyFactory;
import com.github.wegoo.cain.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.NTRULPRimeKey;
import com.github.wegoo.cain.pqc.jcajce.spec.NTRULPRimeParameterSpec;
import com.github.wegoo.cain.util.Arrays;

public class BCNTRULPRimePublicKey
    implements PublicKey, NTRULPRimeKey
{
    private static final long serialVersionUID = 1L;

    private transient NTRULPRimePublicKeyParameters params;

    public BCNTRULPRimePublicKey(
        NTRULPRimePublicKeyParameters params)
    {
        this.params = params;
    }

    public BCNTRULPRimePublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (NTRULPRimePublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this NTRULPRime public key with another object.
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

        if (o instanceof BCNTRULPRimePublicKey)
        {
            BCNTRULPRimePublicKey otherKey = (BCNTRULPRimePublicKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "NTRULPRime"
     */
    public final String getAlgorithm()
    {
        return "NTRULPRime";
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

    public NTRULPRimeParameterSpec getParameterSpec()
    {
        return NTRULPRimeParameterSpec.fromName(params.getParameters().getName());
    }

    NTRULPRimePublicKeyParameters getKeyParams()
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
