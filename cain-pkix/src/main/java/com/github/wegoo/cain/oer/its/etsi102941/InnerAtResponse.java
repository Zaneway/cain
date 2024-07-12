package com.github.wegoo.cain.oer.its.etsi102941;

import com.github.wegoo.cain.asn1.ASN1Encodable;
import com.github.wegoo.cain.asn1.ASN1Object;
import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.asn1.DEROctetString;
import com.github.wegoo.cain.asn1.DERSequence;
import com.github.wegoo.cain.oer.OEROptional;
import com.github.wegoo.cain.oer.its.etsi103097.EtsiTs103097Certificate;
import com.github.wegoo.cain.util.Arrays;

/**
 * InnerAtResponse ::= SEQUENCE {
 * requestHash                   OCTET STRING (SIZE(16)),
 * responseCode                  AuthorizationResponseCode,
 * certificate                   EtsiTs103097Certificate OPTIONAL,
 * ...
 * }
 * (WITH COMPONENTS { responseCode (ok), certificate PRESENT }
 * | WITH COMPONENTS { responseCode (ALL EXCEPT ok), certificate ABSENT }
 * )
 */
public class InnerAtResponse
    extends ASN1Object
{
    private final ASN1OctetString requestHash;
    private final AuthorizationResponseCode responseCode;
    private final EtsiTs103097Certificate certificate;

    public InnerAtResponse(ASN1OctetString requestHash, AuthorizationResponseCode responseCode, EtsiTs103097Certificate certificate)
    {
        this.requestHash = requestHash;
        this.responseCode = responseCode;
        this.certificate = certificate;
    }

    private InnerAtResponse(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("expected sequence size of 3");
        }
        requestHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
        responseCode = AuthorizationResponseCode.getInstance(seq.getObjectAt(1));
        certificate = OEROptional.getValue(EtsiTs103097Certificate.class, seq.getObjectAt(2));
    }

    public static InnerAtResponse getInstance(Object o)
    {
        if (o instanceof InnerAtResponse)
        {
            return (InnerAtResponse)o;
        }

        if (o != null)
        {
            return new InnerAtResponse(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public ASN1OctetString getRequestHash()
    {
        return requestHash;
    }

    public AuthorizationResponseCode getResponseCode()
    {
        return responseCode;
    }

    public EtsiTs103097Certificate getCertificate()
    {
        return certificate;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{requestHash, responseCode, OEROptional.getInstance(certificate)});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private ASN1OctetString requestHash;
        private AuthorizationResponseCode responseCode;
        private EtsiTs103097Certificate certificate;

        public Builder setRequestHash(ASN1OctetString requestHash)
        {
            this.requestHash = requestHash;
            return this;
        }

        public Builder setRequestHash(byte[] requestHash)
        {
            this.requestHash = new DEROctetString(Arrays.clone(requestHash));
            return this;
        }

        public Builder setResponseCode(AuthorizationResponseCode responseCode)
        {
            this.responseCode = responseCode;
            return this;
        }

        public Builder setCertificate(EtsiTs103097Certificate certificate)
        {
            this.certificate = certificate;
            return this;
        }

        public InnerAtResponse createInnerAtResponse()
        {
            return new InnerAtResponse(requestHash, responseCode, certificate);
        }
    }

}
