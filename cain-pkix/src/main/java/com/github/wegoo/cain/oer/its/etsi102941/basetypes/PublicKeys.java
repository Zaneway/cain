package com.github.wegoo.cain.oer.its.etsi102941.basetypes;

import com.github.wegoo.cain.asn1.ASN1Encodable;
import com.github.wegoo.cain.asn1.ASN1Object;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.asn1.DERSequence;
import com.github.wegoo.cain.oer.OEROptional;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;

/**
 * PublicKeys ::= SEQUENCE {
 * verificationKey       PublicVerificationKey,
 * encryptionKey         PublicEncryptionKey OPTIONAL
 * }
 */
public class PublicKeys
    extends ASN1Object
{
    private final PublicVerificationKey verificationKey;
    private final PublicEncryptionKey encryptionKey;

    public PublicKeys(PublicVerificationKey verificationKey, PublicEncryptionKey encryptionKey)
    {
        this.verificationKey = verificationKey;
        this.encryptionKey = encryptionKey;
    }


    public static PublicKeys getInstance(Object o)
    {
        if (o instanceof PublicKeys)
        {
            return (PublicKeys)o;
        }
        if (o != null)
        {
            return new PublicKeys(ASN1Sequence.getInstance(o));
        }
        return null;
    }


    private PublicKeys(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        verificationKey = PublicVerificationKey.getInstance(sequence.getObjectAt(0));
        encryptionKey = OEROptional.getValue(PublicEncryptionKey.class, sequence.getObjectAt(1));
    }


    public PublicVerificationKey getVerificationKey()
    {
        return verificationKey;
    }

    public PublicEncryptionKey getEncryptionKey()
    {
        return encryptionKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{verificationKey, OEROptional.getInstance(encryptionKey)});
    }
}
