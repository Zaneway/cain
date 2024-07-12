package com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes;

import com.github.wegoo.cain.asn1.ASN1Object;
import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.DEROctetString;
import com.github.wegoo.cain.util.Arrays;

/**
 * LinkageSeed ::= OCTET STRING (SIZE(16))
 */
public class LinkageSeed
    extends ASN1Object
{
    private final byte[] linkageSeed;

    public LinkageSeed(byte[] linkageSeed)
    {
        if (linkageSeed.length != 16)
        {
            throw new IllegalArgumentException("linkage seed not 16 bytes");
        }
        this.linkageSeed = Arrays.clone(linkageSeed);
    }

    private LinkageSeed(ASN1OctetString value)
    {
        this(value.getOctets());
    }

    public static LinkageSeed getInstance(Object o)
    {
        if (o instanceof LinkageSeed)
        {
            return (LinkageSeed)o;
        }
        if (o != null)
        {
            return new LinkageSeed(DEROctetString.getInstance(o));
        }
        return null;
    }

    public byte[] getLinkageSeed()
    {
        return linkageSeed;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(linkageSeed);
    }
}
