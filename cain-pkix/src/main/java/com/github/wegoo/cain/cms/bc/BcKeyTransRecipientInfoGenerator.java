package com.github.wegoo.cain.cms.bc;

import com.github.wegoo.cain.asn1.cms.IssuerAndSerialNumber;
import com.github.wegoo.cain.cert.X509CertificateHolder;
import com.github.wegoo.cain.cms.KeyTransRecipientInfoGenerator;
import com.github.wegoo.cain.operator.bc.BcAsymmetricKeyWrapper;

public abstract class BcKeyTransRecipientInfoGenerator
    extends KeyTransRecipientInfoGenerator
{
    public BcKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert, BcAsymmetricKeyWrapper wrapper)
    {
        super(new IssuerAndSerialNumber(recipientCert.toASN1Structure()), wrapper);
    }

    public BcKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, BcAsymmetricKeyWrapper wrapper)
    {
        super(subjectKeyIdentifier, wrapper);
    }
}