package com.github.wegoo.cain.cms;

import java.util.ArrayList;
import java.util.List;

import com.github.wegoo.cain.asn1.ASN1Set;
import com.github.wegoo.cain.asn1.cms.OriginatorInfo;
import com.github.wegoo.cain.cert.X509CertificateHolder;
import com.github.wegoo.cain.util.Store;

public class OriginatorInfoGenerator
{
    private final List origCerts;
    private final List origCRLs;

    public OriginatorInfoGenerator(X509CertificateHolder origCert)
    {
        this.origCerts = new ArrayList(1);
        this.origCRLs = null;
        origCerts.add(origCert.toASN1Structure());
    }

    public OriginatorInfoGenerator(Store origCerts)
        throws CMSException
    {
        this(origCerts, null);
    }

    public OriginatorInfoGenerator(Store origCerts, Store origCRLs)
        throws CMSException
    {
        if (origCerts != null)
        {
            this.origCerts = CMSUtils.getCertificatesFromStore(origCerts);
        }
        else
        {
            this.origCerts = null;
        }

        if (origCRLs != null)
        {
            this.origCRLs = CMSUtils.getCRLsFromStore(origCRLs);
        }
        else
        {
            this.origCRLs = null;
        }
    }

    public OriginatorInformation generate()
    {
        ASN1Set certSet = origCerts == null ? null : CMSUtils.createDerSetFromList(origCerts);
        ASN1Set crlSet = origCRLs == null ? null : CMSUtils.createDerSetFromList(origCRLs);
        return new OriginatorInformation(new OriginatorInfo(certSet, crlSet));
    }
}
