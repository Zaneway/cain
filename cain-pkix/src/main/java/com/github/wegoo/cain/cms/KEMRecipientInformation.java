package com.github.wegoo.cain.cms;

import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.asn1.cms.IssuerAndSerialNumber;
import com.github.wegoo.cain.asn1.cms.KEMRecipientInfo;
import com.github.wegoo.cain.asn1.cms.RecipientIdentifier;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;

public class KEMRecipientInformation
    extends RecipientInformation
{
    private KEMRecipientInfo info;

    KEMRecipientInformation(
        KEMRecipientInfo        info,
        AlgorithmIdentifier     messageAlgorithm,
        CMSSecureReadable       secureReadable)
    {
        super(info.getKem(), messageAlgorithm, secureReadable);

        this.info = info;

        RecipientIdentifier r = info.getRecipientIdentifier();

        if (r.isTagged())
        {
            ASN1OctetString octs = ASN1OctetString.getInstance(r.getId());

            rid = new KeyTransRecipientId(octs.getOctets());   // TODO: should be KEM
        }
        else
        {
            IssuerAndSerialNumber iAnds = IssuerAndSerialNumber.getInstance(r.getId());

            rid = new KeyTransRecipientId(iAnds.getName(), iAnds.getSerialNumber().getValue());    // TODO:
        }
    }

    protected RecipientOperator getRecipientOperator(Recipient recipient)
        throws CMSException
    {
        return ((KEMRecipient)recipient).getRecipientOperator(new AlgorithmIdentifier(keyEncAlg.getAlgorithm(), info), messageAlgorithm, info.getEncryptedKey().getOctets());
    }
}
