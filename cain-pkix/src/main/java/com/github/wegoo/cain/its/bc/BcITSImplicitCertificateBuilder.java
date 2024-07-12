package com.github.wegoo.cain.its.bc;

import com.github.wegoo.cain.its.ITSCertificate;
import com.github.wegoo.cain.its.ITSImplicitCertificateBuilder;
import com.github.wegoo.cain.oer.its.ieee1609dot2.ToBeSignedCertificate;
import com.github.wegoo.cain.operator.bc.BcDigestCalculatorProvider;

public class BcITSImplicitCertificateBuilder
    extends ITSImplicitCertificateBuilder
{
    public BcITSImplicitCertificateBuilder(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(issuer, new BcDigestCalculatorProvider(), tbsCertificate);
    }
}
