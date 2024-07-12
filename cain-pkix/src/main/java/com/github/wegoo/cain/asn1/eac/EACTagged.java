package com.github.wegoo.cain.asn1.eac;

import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.asn1.ASN1TaggedObject;
import com.github.wegoo.cain.asn1.BERTags;
import com.github.wegoo.cain.asn1.DEROctetString;
import com.github.wegoo.cain.asn1.DERTaggedObject;

class EACTagged
{
    static ASN1TaggedObject create(int eacTag, ASN1Sequence seq)
    {
        return new DERTaggedObject(false, BERTags.APPLICATION, eacTag, seq);
    }

    static ASN1TaggedObject create(int eacTag, PublicKeyDataObject key)
    {
        return new DERTaggedObject(false, BERTags.APPLICATION, eacTag, key);
    }

    static ASN1TaggedObject create(int eacTag, byte[] octets)
    {
        return new DERTaggedObject(false, BERTags.APPLICATION, eacTag, new DEROctetString(octets));
    }
}
