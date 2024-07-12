package com.github.wegoo.cain.asn1.cms;

import com.github.wegoo.cain.asn1.ASN1EncodableVector;
import com.github.wegoo.cain.asn1.ASN1Integer;
import com.github.wegoo.cain.asn1.ASN1Object;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.DEROctetString;
import com.github.wegoo.cain.asn1.DERSequence;
import com.github.wegoo.cain.asn1.DERTaggedObject;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 *  CMSORIforKEMOtherInfo ::= SEQUENCE {
 *     wrap KeyEncryptionAlgorithmIdentifier,
 *     kekLength INTEGER (1..MAX),
 *     ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL
 *   }
 *
 *   UserKeyingMaterial ::= OCTET STRING
 * </pre>
 */
public class CMSORIforKEMOtherInfo
    extends ASN1Object
{
    private final AlgorithmIdentifier wrap;
    private final int kekLength;
    private final byte[] ukm;

    public CMSORIforKEMOtherInfo(AlgorithmIdentifier wrap, int kekLength)
    {
        this(wrap, kekLength, null);
    }

    public CMSORIforKEMOtherInfo(AlgorithmIdentifier wrap, int kekLength, byte[] ukm)
    {
        this.wrap = wrap;
        this.kekLength = kekLength;
        this.ukm = ukm;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(wrap);
        v.add(new ASN1Integer(kekLength));

        if (ukm != null)
        {
            v.add(new DERTaggedObject(true, 0, new DEROctetString(ukm)));
        }
        return new DERSequence(v);
    }
}
