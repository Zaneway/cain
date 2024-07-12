package com.github.wegoo.cain.jcajce.provider.asymmetric.edec;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.crypto.util.PrivateKeyFactory;
import com.github.wegoo.cain.crypto.util.PublicKeyFactory;

/**
 * utility class for converting jce/jca XDH, and EdDSA
 * objects into their com.github.wegoo.cain.crypto counterparts.
 */
class EdECUtil
{
    public static AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey key)
        throws InvalidKeyException
    {
        if (key instanceof BCXDHPublicKey)
        {
            return ((BCXDHPublicKey)key).engineGetKeyParameters();
        }
        else if (key instanceof BCEdDSAPublicKey)
        {
            return ((BCEdDSAPublicKey)key).engineGetKeyParameters();
        }
        else
        {
            // see if we can build a key from key.getEncoded()
            try
            {
                byte[] bytes = key.getEncoded();

                if (bytes == null)
                {
                    throw new InvalidKeyException("no encoding for EdEC/XDH public key");
                }

                return PublicKeyFactory.createKey(bytes);
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("cannot identify EdEC/XDH public key: " + e.getMessage());
            }
        }
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey key)
        throws InvalidKeyException
    {
        if (key instanceof BCXDHPrivateKey)
        {
            return ((BCXDHPrivateKey)key).engineGetKeyParameters();
        }
        else if (key instanceof BCEdDSAPrivateKey)
        {
            return ((BCEdDSAPrivateKey)key).engineGetKeyParameters();
        }
        else
        {
            // see if we can build a key from key.getEncoded()
            try
            {
                byte[] bytes = key.getEncoded();

                if (bytes == null)
                {
                    throw new InvalidKeyException("no encoding for EdEC/XDH private key");
                }

                return PrivateKeyFactory.createKey(bytes);
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("cannot identify EdEC/XDH private key: " + e.getMessage());
            }
        }
    }
}
