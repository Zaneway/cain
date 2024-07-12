package com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes;

import com.github.wegoo.cain.asn1.ASN1OctetString;

public class HashedId8
    extends HashedId
{
    public HashedId8(byte[] string)
    {
        super(string);
        if (string.length != 8)
        {
            throw new IllegalArgumentException("hash id not 8 bytes");
        }
    }

    public static HashedId8 getInstance(Object src)
    {
        if (src instanceof HashedId8)
        {
            return (HashedId8)src;
        }

        if (src != null)
        {
            byte[] octetString = ASN1OctetString.getInstance(src).getOctets();
            return new HashedId8(octetString);
        }

        return null;
    }
}
