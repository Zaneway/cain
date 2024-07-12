package com.github.wegoo.cain.operator.bc;

import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.crypto.Digest;
import com.github.wegoo.cain.crypto.Signer;
import com.github.wegoo.cain.crypto.signers.DSADigestSigner;
import com.github.wegoo.cain.crypto.signers.ECDSASigner;
import com.github.wegoo.cain.operator.OperatorCreationException;

public class BcECContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcECContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
    {
        super(sigAlgId, digAlgId);
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        Digest dig = digestProvider.get(digAlgId);

        return new DSADigestSigner(new ECDSASigner(), dig);
    }
}
