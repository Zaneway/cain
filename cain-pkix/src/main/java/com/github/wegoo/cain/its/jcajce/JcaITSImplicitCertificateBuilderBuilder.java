package com.github.wegoo.cain.its.jcajce;

import java.security.Provider;

import com.github.wegoo.cain.its.ITSCertificate;
import com.github.wegoo.cain.its.ITSImplicitCertificateBuilder;
import com.github.wegoo.cain.oer.its.ieee1609dot2.ToBeSignedCertificate;
import com.github.wegoo.cain.operator.OperatorCreationException;
import com.github.wegoo.cain.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class JcaITSImplicitCertificateBuilderBuilder
{
    private final JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();

    public JcaITSImplicitCertificateBuilderBuilder setProvider(Provider provider)
    {
        this.digestCalculatorProviderBuilder.setProvider(provider);

        return this;
    }

    public JcaITSImplicitCertificateBuilderBuilder setProvider(String providerName)
    {
        this.digestCalculatorProviderBuilder.setProvider(providerName);

        return this;
    }

    public ITSImplicitCertificateBuilder build(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificate)
        throws OperatorCreationException
    {
        return new ITSImplicitCertificateBuilder(issuer, digestCalculatorProviderBuilder.build(), tbsCertificate);
    }
}
