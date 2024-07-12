package com.github.wegoo.cain.its.bc;

import com.github.wegoo.cain.asn1.ASN1Encodable;
import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.nist.NISTNamedCurves;
import com.github.wegoo.cain.asn1.sec.SECObjectIdentifiers;
import com.github.wegoo.cain.asn1.teletrust.TeleTrusTNamedCurves;
import com.github.wegoo.cain.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.github.wegoo.cain.asn1.x9.X9ECParameters;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.crypto.params.ECNamedDomainParameters;
import com.github.wegoo.cain.crypto.params.ECPublicKeyParameters;
import com.github.wegoo.cain.its.ITSPublicVerificationKey;
import com.github.wegoo.cain.math.ec.ECCurve;
import com.github.wegoo.cain.math.ec.ECPoint;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.EccCurvePoint;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.Point256;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.Point384;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;

public class BcITSPublicVerificationKey
    extends ITSPublicVerificationKey
{
    public BcITSPublicVerificationKey(PublicVerificationKey verificationKey)
    {
        super(verificationKey);
    }

    static PublicVerificationKey fromKeyParameters(ECPublicKeyParameters pubKey)
    {
        ASN1ObjectIdentifier curveID = ((ECNamedDomainParameters)pubKey.getParameters()).getName();
        ECPoint q = pubKey.getQ();

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaNistP256,
                EccP256CurvePoint.uncompressedP256(
                    Point256.builder()
                        .setX(q.getAffineXCoord().toBigInteger())
                        .setY(q.getAffineYCoord().toBigInteger())
                        .createPoint256()
                ));
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaBrainpoolP256r1,
                EccP256CurvePoint
                    .uncompressedP256(Point256.builder()
                        .setX(q.getAffineXCoord().toBigInteger())
                        .setY(q.getAffineYCoord().toBigInteger())
                        .createPoint256()));
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaBrainpoolP384r1,
                EccP384CurvePoint.uncompressedP384(Point384.builder()
                    .setX(q.getAffineXCoord().toBigInteger())
                    .setY(q.getAffineYCoord().toBigInteger())
                    .createPoint384()));

        }
        else
        {
            throw new IllegalArgumentException("unknown curve in public encryption key");
        }
    }

    public BcITSPublicVerificationKey(AsymmetricKeyParameter verificationKey)
    {
        super(fromKeyParameters((ECPublicKeyParameters)verificationKey));
    }

    public AsymmetricKeyParameter getKey()
    {
        X9ECParameters params;
        ASN1ObjectIdentifier curveID;

        switch (verificationKey.getChoice())
        {
        case PublicVerificationKey.ecdsaNistP256:
            curveID = SECObjectIdentifiers.secp256r1;
            params = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP256r1:
            curveID = TeleTrusTObjectIdentifiers.brainpoolP256r1;
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP384r1:
            curveID = TeleTrusTObjectIdentifiers.brainpoolP384r1;
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP384r1);
            break;
        default:
            throw new IllegalStateException("unknown key type");
        }
        ECCurve curve = params.getCurve();

        ASN1Encodable pviCurvePoint = verificationKey.getPublicVerificationKey();
        final EccCurvePoint itsPoint;
        if (pviCurvePoint instanceof EccCurvePoint)
        {
            itsPoint = (EccCurvePoint)verificationKey.getPublicVerificationKey();
        }
        else
        {
            throw new IllegalStateException("extension to public verification key not supported");
        }

        byte[] key;

        if (itsPoint instanceof EccP256CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else if (itsPoint instanceof EccP384CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else
        {
            throw new IllegalStateException("unknown key type");
        }

        ECPoint point = curve.decodePoint(key).normalize();
        return new ECPublicKeyParameters(point,
            new ECNamedDomainParameters(curveID, params));
    }
}
