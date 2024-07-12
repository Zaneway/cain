package com.github.wegoo.cain.oer.its.etsi103097;

import com.github.wegoo.cain.asn1.ASN1Integer;
import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.oer.its.ieee1609dot2.CertificateBase;
import com.github.wegoo.cain.oer.its.ieee1609dot2.CertificateType;
import com.github.wegoo.cain.oer.its.ieee1609dot2.ExplicitCertificate;
import com.github.wegoo.cain.oer.its.ieee1609dot2.IssuerIdentifier;
import com.github.wegoo.cain.oer.its.ieee1609dot2.ToBeSignedCertificate;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.Signature;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.UINT8;

public class EtsiTs103097Certificate
    extends ExplicitCertificate
{

    public EtsiTs103097Certificate(UINT8 version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, Signature signature)
    {
        super(version, issuer, toBeSignedCertificate, signature);
    }

    protected EtsiTs103097Certificate(ASN1Sequence instance)
    {
        super(instance);
    }

    public static EtsiTs103097Certificate getInstance(Object src)
    {
        if (src instanceof EtsiTs103097Certificate)
        {
            return (EtsiTs103097Certificate)src;
        }
        if (src != null)
        {
            return new EtsiTs103097Certificate(ASN1Sequence.getInstance(src));
        }

        return null;
    }

}
