package com.github.wegoo.cain.cms;

import com.github.wegoo.cain.asn1.cms.RecipientInfo;
import com.github.wegoo.cain.operator.GenericKey;

public interface RecipientInfoGenerator
{
    RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException;
}
