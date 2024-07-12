package com.github.wegoo.cain.oer.its.etsi102941;

import com.github.wegoo.cain.asn1.ASN1Boolean;
import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.oer.its.etsi102941.basetypes.Version;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.Time32;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.UINT8;

/**
 * DeltaCtl::= CtlFormat (WITH COMPONENTS {...,
 * isFullCtl(FALSE)
 * })
 */
public class DeltaCtl
    extends CtlFormat
{
    public DeltaCtl(Version version, Time32 nextUpdate, UINT8 ctlSequence, SequenceOfCtlCommand ctlCommands)
    {
        super(version, nextUpdate, ASN1Boolean.FALSE, ctlSequence, ctlCommands);
    }

    private DeltaCtl(ASN1Sequence seq)
    {
        super(seq);
    }

    public static DeltaCtl getInstance(Object o)
    {
        if (o instanceof DeltaCtl)
        {
            return (DeltaCtl)o;
        }

        if (o != null)
        {
            return new DeltaCtl(ASN1Sequence.getInstance(o));
        }

        return null;
    }

}
