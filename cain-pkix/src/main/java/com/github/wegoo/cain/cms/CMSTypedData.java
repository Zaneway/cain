package com.github.wegoo.cain.cms;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;

public interface CMSTypedData
    extends CMSProcessable
{
    ASN1ObjectIdentifier getContentType();
}
