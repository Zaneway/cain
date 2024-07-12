package com.github.wegoo.cain.operator.bc;

import com.github.wegoo.cain.asn1.edec.EdECObjectIdentifiers;
import com.github.wegoo.cain.asn1.nist.NISTObjectIdentifiers;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.crypto.Signer;
import com.github.wegoo.cain.crypto.signers.Ed25519Signer;
import com.github.wegoo.cain.operator.OperatorCreationException;

public class BcEdECContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcEdECContentSignerBuilder(AlgorithmIdentifier sigAlgId)
    {
        super(sigAlgId, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512));
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        if (sigAlgId.getAlgorithm().equals(EdECObjectIdentifiers.id_Ed25519))
        {
            return new Ed25519Signer();
        }

        throw new IllegalStateException("unknown signature type");
    }
}
