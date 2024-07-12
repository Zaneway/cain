package com.github.wegoo.cain.cms;

import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;

public interface KEKRecipient
    extends Recipient
{
    RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey)
        throws CMSException;
}
