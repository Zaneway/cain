package com.github.wegoo.cain.cms;

import java.io.IOException;
import java.io.InputStream;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.ASN1Set;

interface CMSSecureReadable
{
    ASN1ObjectIdentifier getContentType();

    InputStream getInputStream()
            throws IOException, CMSException;

    ASN1Set getAuthAttrSet();

    void setAuthAttrSet(ASN1Set set);

    boolean hasAdditionalData();
}
