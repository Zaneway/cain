package com.github.wegoo.cain.jcajce.provider.asymmetric.edec;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import com.github.wegoo.cain.crypto.CryptoException;
import com.github.wegoo.cain.crypto.Signer;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.crypto.params.Ed25519PrivateKeyParameters;
import com.github.wegoo.cain.crypto.params.Ed25519PublicKeyParameters;
import com.github.wegoo.cain.crypto.params.Ed448PrivateKeyParameters;
import com.github.wegoo.cain.crypto.params.Ed448PublicKeyParameters;
import com.github.wegoo.cain.crypto.signers.Ed25519Signer;
import com.github.wegoo.cain.crypto.signers.Ed448Signer;

public class SignatureSpi
    extends java.security.SignatureSpi
{
    private static final byte[] EMPTY_CONTEXT = new byte[0];

    private final String algorithm;

    private Signer signer;

    SignatureSpi(String algorithm)
    {
        this.algorithm = algorithm;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        AsymmetricKeyParameter pub = getLwEdDSAKeyPublic(publicKey);

        if (pub instanceof Ed25519PublicKeyParameters)
        {
            signer = getSigner("Ed25519");
        }
        else if (pub instanceof Ed448PublicKeyParameters)
        {
            signer = getSigner("Ed448");
        }
        else
        {
            throw new InvalidKeyException("unsupported public key type");
        }

        signer.init(false, pub);
    }

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        AsymmetricKeyParameter priv = getLwEdDSAKeyPrivate(privateKey);

        if (priv instanceof Ed25519PrivateKeyParameters)
        {
            signer = getSigner("Ed25519");
        }
        else if (priv instanceof Ed448PrivateKeyParameters)
        {
            signer = getSigner("Ed448");
        }
        else
        {
            throw new InvalidKeyException("unsupported private key type");
        }

        signer.init(true, priv);
    }

    private static AsymmetricKeyParameter getLwEdDSAKeyPrivate(PrivateKey key)
        throws InvalidKeyException
    {
        return EdECUtil.generatePrivateKeyParameter(key);
    }

    private static AsymmetricKeyParameter getLwEdDSAKeyPublic(PublicKey key)
        throws InvalidKeyException
    {
        return EdECUtil.generatePublicKeyParameter(key);
    }

    private Signer getSigner(String alg)
        throws InvalidKeyException
    {
        if (algorithm != null && !alg.equals(algorithm))
        {
            throw new InvalidKeyException("inappropriate key for " + algorithm);
        }

        if (alg.equals("Ed448"))
        {
            return new Ed448Signer(EMPTY_CONTEXT);
        }
        else
        {
            return new Ed25519Signer();
        }
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        signer.update(b);
    }

    protected void engineUpdate(byte[] bytes, int off, int len)
        throws SignatureException
    {
        signer.update(bytes, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            return signer.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new SignatureException(e.getMessage());
        }
    }

    protected boolean engineVerify(byte[] signature)
        throws SignatureException
    {
        return signer.verifySignature(signature);
    }

    protected void engineSetParameter(String s, Object o)
        throws InvalidParameterException
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected Object engineGetParameter(String s)
        throws InvalidParameterException
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    public final static class EdDSA
        extends SignatureSpi
    {
        public EdDSA()
        {
            super(null);
        }
    }

    public final static class Ed448
        extends SignatureSpi
    {
        public Ed448()
        {
            super("Ed448");
        }
    }

    public final static class Ed25519
        extends SignatureSpi
    {
        public Ed25519()
        {
            super("Ed25519");
        }
    }
}
