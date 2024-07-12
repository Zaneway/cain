package com.github.wegoo.cain.operator.bc;

import java.io.IOException;

import com.github.wegoo.cain.asn1.edec.EdECObjectIdentifiers;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.crypto.Signer;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.crypto.signers.Ed25519Signer;
import com.github.wegoo.cain.crypto.signers.Ed448Signer;
import com.github.wegoo.cain.crypto.util.PublicKeyFactory;
import com.github.wegoo.cain.operator.OperatorCreationException;

public class BcEdDSAContentVerifierProviderBuilder
    extends BcContentVerifierProviderBuilder
{
    public static final byte[] DEFAULT_CONTEXT = new byte[0];

    public BcEdDSAContentVerifierProviderBuilder()
    {
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId)
        throws OperatorCreationException
    {
        if (sigAlgId.getAlgorithm().equals(EdECObjectIdentifiers.id_Ed448))
        {
            return new Ed448Signer(DEFAULT_CONTEXT);
        }
        else
        {
            return new Ed25519Signer();
        }
    }

    protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }
}