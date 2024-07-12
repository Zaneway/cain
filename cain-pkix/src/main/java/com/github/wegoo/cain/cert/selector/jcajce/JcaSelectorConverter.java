package com.github.wegoo.cain.cert.selector.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CertSelector;

import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.asn1.x500.X500Name;
import com.github.wegoo.cain.cert.selector.X509CertificateHolderSelector;

public class JcaSelectorConverter
{
    public JcaSelectorConverter()
    {

    }

    public X509CertificateHolderSelector getCertificateHolderSelector(X509CertSelector certSelector)
    {
        try
        {
            X500Name issuer = X500Name.getInstance(certSelector.getIssuerAsBytes());
            BigInteger serialNumber = certSelector.getSerialNumber();
            byte[] subjectKeyId = null;

            byte[] subjectKeyIdentifier = certSelector.getSubjectKeyIdentifier();
            if (subjectKeyIdentifier != null)
            {
                subjectKeyId = ASN1OctetString.getInstance(subjectKeyIdentifier).getOctets();
            }

            return new X509CertificateHolderSelector(issuer, serialNumber, subjectKeyId);
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("unable to convert issuer: " + e.getMessage());
        }
    }
}
