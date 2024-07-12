package com.github.wegoo.cain.asn1.smime;

import com.github.wegoo.cain.asn1.DERSequence;
import com.github.wegoo.cain.asn1.DERSet;
import com.github.wegoo.cain.asn1.cms.Attribute;

public class SMIMECapabilitiesAttribute
    extends Attribute
{
    public SMIMECapabilitiesAttribute(
        SMIMECapabilityVector capabilities)
    {
        super(SMIMEAttributes.smimeCapabilities,
                new DERSet(new DERSequence(capabilities.toASN1EncodableVector())));
    }
}
