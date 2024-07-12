package com.github.wegoo.cain.pkcs.bc;

import java.io.IOException;

import com.github.wegoo.cain.asn1.x500.X500Name;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.crypto.util.SubjectPublicKeyInfoFactory;
import com.github.wegoo.cain.pkcs.PKCS10CertificationRequestBuilder;

/**
 * Extension of the PKCS#10 builder to support AsymmetricKey objects.
 */
public class BcPKCS10CertificationRequestBuilder
    extends PKCS10CertificationRequestBuilder
{
    /**
     * Create a PKCS#10 builder for the passed in subject and JCA public key.
     *
     * @param subject an X500Name containing the subject associated with the request we are building.
     * @param publicKey a JCA public key that is to be associated with the request we are building.
     * @throws IOException if there is a problem encoding the public key.
     */
    public BcPKCS10CertificationRequestBuilder(X500Name subject, AsymmetricKeyParameter publicKey)
        throws IOException
    {
        super(subject, SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
    }
}
