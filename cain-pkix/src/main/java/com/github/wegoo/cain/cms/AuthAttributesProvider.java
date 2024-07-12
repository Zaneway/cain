package com.github.wegoo.cain.cms;

import com.github.wegoo.cain.asn1.ASN1Set;

interface AuthAttributesProvider
{
    ASN1Set getAuthAttributes();

    boolean isAead();
}
