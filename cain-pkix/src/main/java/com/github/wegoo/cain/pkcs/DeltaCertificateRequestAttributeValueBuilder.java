package com.github.wegoo.cain.pkcs;

import com.github.wegoo.cain.asn1.ASN1EncodableVector;
import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.DERSequence;
import com.github.wegoo.cain.asn1.DERSet;
import com.github.wegoo.cain.asn1.DERTaggedObject;
import com.github.wegoo.cain.asn1.pkcs.Attribute;
import com.github.wegoo.cain.asn1.x500.X500Name;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;

public class DeltaCertificateRequestAttributeValueBuilder
{
    private final SubjectPublicKeyInfo subjectPublicKey;

    private AlgorithmIdentifier signatureAlgorithm;
    private X500Name subject;

    public DeltaCertificateRequestAttributeValueBuilder(SubjectPublicKeyInfo subjectPublicKey)
    {
        this.subjectPublicKey = subjectPublicKey;
    }

    public DeltaCertificateRequestAttributeValueBuilder setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm)
    {
       this.signatureAlgorithm = signatureAlgorithm;

       return this;
    }

    public DeltaCertificateRequestAttributeValueBuilder setSubject(X500Name subject)
    {
       this.subject = subject;

       return this;
    }

    public DeltaCertificateRequestAttributeValue build()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (subject != null)
        {
            v.add(new DERTaggedObject(false, 0, subject));
        }
        v.add(subjectPublicKey);
        if (signatureAlgorithm != null)
        {
            v.add(new DERTaggedObject(false, 2, signatureAlgorithm));
        }

        
        return new DeltaCertificateRequestAttributeValue(new Attribute(new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.2"),
                        new DERSet(new DERSequence(v))));
    }
}
