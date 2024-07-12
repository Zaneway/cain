package com.github.wegoo.cain.oer.its.etsi102941;

import com.github.wegoo.cain.asn1.ASN1Boolean;
import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.oer.its.etsi102941.basetypes.Version;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.Time32;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.UINT8;

public class ToBeSignedRcaCtl
    extends CtlFormat
{
    public ToBeSignedRcaCtl(Version version, Time32 nextUpdate, ASN1Boolean isFullCtl, UINT8 ctlSequence, SequenceOfCtlCommand ctlCommands)
    {
        super(version, nextUpdate, isFullCtl, ctlSequence, ctlCommands);
    }

    protected ToBeSignedRcaCtl(ASN1Sequence seq)
    {
        super(seq);
    }

    public static ToBeSignedRcaCtl getInstance(Object o)
    {
        if (o instanceof ToBeSignedRcaCtl)
        {
            return (ToBeSignedRcaCtl)o;
        }

        if (o != null)
        {
            return new ToBeSignedRcaCtl(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
