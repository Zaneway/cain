package com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes;

import com.github.wegoo.cain.asn1.ASN1Object;

/**
 * Common interface for ITS curve points.
 */
public abstract class EccCurvePoint
    extends ASN1Object
{
    public abstract byte[] getEncodedPoint();
}
