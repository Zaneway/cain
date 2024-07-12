package com.github.wegoo.cain.cert.jcajce;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import com.github.wegoo.cain.asn1.x500.X500Name;
import com.github.wegoo.cain.cert.AttributeCertificateIssuer;

public class JcaAttributeCertificateIssuer
    extends AttributeCertificateIssuer
{
    /**
     * Base constructor.
     *
     * @param issuerCert certificate for the issuer of the attribute certificate.
     */
    public JcaAttributeCertificateIssuer(X509Certificate issuerCert)
    {
        this(issuerCert.getIssuerX500Principal());
    }

    /**
     * Base constructor.
     *
     * @param issuerDN X.500 DN for the issuer of the attribute certificate.
     */
    public JcaAttributeCertificateIssuer(X500Principal issuerDN)
    {
        super(X500Name.getInstance(issuerDN.getEncoded()));
    }
}
