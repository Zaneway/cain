package com.github.wegoo.cain.oer.its.etsi103097;

import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class EtsiTs103097DataUnsecured
    extends EtsiTs103097Data
{
    public EtsiTs103097DataUnsecured(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected EtsiTs103097DataUnsecured(ASN1Sequence src)
    {
        super(src);
    }

    public static EtsiTs103097DataUnsecured getInstance(Object o)
    {
        if (o instanceof EtsiTs103097DataUnsecured)
        {
            return (EtsiTs103097DataUnsecured)o;
        }
        if (o != null)
        {
            return new EtsiTs103097DataUnsecured(ASN1Sequence.getInstance(o));
        }
        return null;
    }

}
