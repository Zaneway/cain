package com.github.wegoo.cain.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Enumeration;

import com.github.wegoo.cain.asn1.ASN1BitString;
import com.github.wegoo.cain.asn1.ASN1Encodable;
import com.github.wegoo.cain.asn1.ASN1Encoding;
import com.github.wegoo.cain.asn1.ASN1Integer;
import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.pkcs.PrivateKeyInfo;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.asn1.x9.ECNamedCurveTable;
import com.github.wegoo.cain.asn1.x9.X962Parameters;
import com.github.wegoo.cain.asn1.x9.X9ObjectIdentifiers;
import com.github.wegoo.cain.crypto.params.ECDomainParameters;
import com.github.wegoo.cain.crypto.params.ECNamedDomainParameters;
import com.github.wegoo.cain.crypto.params.ECPrivateKeyParameters;
import com.github.wegoo.cain.jcajce.provider.asymmetric.util.EC5Util;
import com.github.wegoo.cain.jcajce.provider.asymmetric.util.ECUtil;
import com.github.wegoo.cain.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import com.github.wegoo.cain.jcajce.provider.config.ProviderConfiguration;
import com.github.wegoo.cain.jce.interfaces.ECPointEncoder;
import com.github.wegoo.cain.jce.interfaces.PKCS12BagAttributeCarrier;
import com.github.wegoo.cain.jce.provider.CainJCEProvider;
import com.github.wegoo.cain.jce.spec.ECNamedCurveParameterSpec;
import com.github.wegoo.cain.math.ec.ECCurve;
import com.github.wegoo.cain.util.Arrays;

public class BCECPrivateKey
    implements ECPrivateKey, com.github.wegoo.cain.jce.interfaces.ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder
{
    static final long serialVersionUID = 994553197664784084L;

    private String algorithm = "EC";
    private boolean withCompression;

    private transient BigInteger d;
    private transient ECParameterSpec ecSpec;
    private transient ProviderConfiguration configuration;
    private transient ASN1BitString publicKey;
    private transient PrivateKeyInfo privateKeyInfo;
    private transient byte[] encoding;

    private transient ECPrivateKeyParameters baseKey;
    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();


    protected BCECPrivateKey()
    {
    }

    public BCECPrivateKey(
        ECPrivateKey key,
        ProviderConfiguration configuration)
    {
        this.d = key.getS();
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
        this.configuration = configuration;
        this.baseKey = convertToBaseKey(this);
    }

    public BCECPrivateKey(
        String algorithm,
        com.github.wegoo.cain.jce.spec.ECPrivateKeySpec spec,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.d = spec.getD();

        if (spec.getParams() != null) // can be null if implicitlyCA
        {
            ECCurve curve = spec.getParams().getCurve();
            EllipticCurve ellipticCurve;

            ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

            this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
        }
        else
        {
            this.ecSpec = null;
        }

        this.configuration = configuration;
        this.baseKey = convertToBaseKey(this);
    }


    public BCECPrivateKey(
        String algorithm,
        ECPrivateKeySpec spec,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.d = spec.getS();
        this.ecSpec = spec.getParams();
        this.configuration = configuration;
        this.baseKey = convertToBaseKey(this);
    }

    public BCECPrivateKey(
        String algorithm,
        BCECPrivateKey key)
    {
        this.algorithm = algorithm;
        this.d = key.d;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.attrCarrier = key.attrCarrier;
        this.publicKey = key.publicKey;
        this.configuration = key.configuration;
        this.baseKey = key.baseKey;
    }

    public BCECPrivateKey(
        String algorithm,
        ECPrivateKeyParameters params,
        BCECPublicKey pubKey,
        ECParameterSpec spec,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.d = params.getD();
        this.configuration = configuration;
        this.baseKey = params;

        if (spec == null)
        {
            ECDomainParameters dp = params.getParameters();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(dp.getG()),
                dp.getN(),
                dp.getH().intValue());
        }
        else
        {
            this.ecSpec = spec;
        }

        this.publicKey = getPublicKeyDetails(pubKey);
    }

    public BCECPrivateKey(
        String algorithm,
        ECPrivateKeyParameters params,
        BCECPublicKey pubKey,
        com.github.wegoo.cain.jce.spec.ECParameterSpec spec,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.d = params.getD();
        this.configuration = configuration;
        this.baseKey = params;

        if (spec == null)
        {
            ECDomainParameters dp = params.getParameters();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(dp.getG()),
                dp.getN(),
                dp.getH().intValue());
        }
        else
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

            this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec);
        }

        try
        {
            this.publicKey = getPublicKeyDetails(pubKey);
        }
        catch (Exception e)
        {
            this.publicKey = null; // not all curves are encodable
        }
    }

    public BCECPrivateKey(
        String algorithm,
        ECPrivateKeyParameters params,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.d = params.getD();
        this.ecSpec = null;
        this.configuration = configuration;
        this.baseKey = params;
    }

    BCECPrivateKey(
        String algorithm,
        PrivateKeyInfo info,
        ProviderConfiguration configuration)
        throws IOException
    {
        this.algorithm = algorithm;
        this.configuration = configuration;
        populateFromPrivKeyInfo(info);
    }

    private void populateFromPrivKeyInfo(PrivateKeyInfo info)
        throws IOException
    {
        X962Parameters params = X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());

        ECCurve curve = EC5Util.getCurve(configuration, params);
        ecSpec = EC5Util.convertToSpec(params, curve);

        ASN1Encodable privKey = info.parsePrivateKey();
        if (privKey instanceof ASN1Integer)
        {
            ASN1Integer derD = ASN1Integer.getInstance(privKey);

            this.d = derD.getValue();
        }
        else
        {
            com.github.wegoo.cain.asn1.sec.ECPrivateKey ec = com.github.wegoo.cain.asn1.sec.ECPrivateKey.getInstance(privKey);

            this.d = ec.getKey();
            this.publicKey = ec.getPublicKey();
        }
        this.baseKey = convertToBaseKey(this);
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        if (encoding == null)
        {
            PrivateKeyInfo info = getPrivateKeyInfo();

            if (info == null)
            {
                return null;
            }

            try
            {
                encoding = info.getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                return null;
            }
        }

        return Arrays.clone(encoding);
    }

    private PrivateKeyInfo getPrivateKeyInfo()
    {
        if (privateKeyInfo == null)
        {
            X962Parameters params = ECUtils.getDomainParametersFromName(ecSpec, withCompression);

            int orderBitLength;
            if (ecSpec == null)
            {
                orderBitLength = ECUtil.getOrderBitLength(configuration, null, this.getS());
            }
            else
            {
                orderBitLength = ECUtil.getOrderBitLength(configuration, ecSpec.getOrder(), this.getS());
            }

            com.github.wegoo.cain.asn1.sec.ECPrivateKey keyStructure;

            if (publicKey != null)
            {
                keyStructure = new com.github.wegoo.cain.asn1.sec.ECPrivateKey(orderBitLength, this.getS(), publicKey, params);
            }
            else
            {
                keyStructure = new com.github.wegoo.cain.asn1.sec.ECPrivateKey(orderBitLength, this.getS(), params);
            }

            try
            {
                privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), keyStructure);
            }
            catch (IOException e)
            {
                return null;
            }
        }

        return privateKeyInfo;
    }

    public ECPrivateKeyParameters engineGetKeyParameters()
    {
        return baseKey;
    }

    public ECParameterSpec getParams()
    {
        return ecSpec;
    }

    public com.github.wegoo.cain.jce.spec.ECParameterSpec getParameters()
    {
        if (ecSpec == null)
        {
            return null;
        }

        return EC5Util.convertSpec(ecSpec);
    }

    com.github.wegoo.cain.jce.spec.ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return EC5Util.convertSpec(ecSpec);
        }

        return configuration.getEcImplicitlyCa();
    }

    public BigInteger getS()
    {
        return d;
    }

    public BigInteger getD()
    {
        return d;
    }

    public void setBagAttribute(
        ASN1ObjectIdentifier oid,
        ASN1Encodable attribute)
    {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public ASN1Encodable getBagAttribute(
        ASN1ObjectIdentifier oid)
    {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return attrCarrier.getBagAttributeKeys();
    }

    public void setPointFormat(String style)
    {
        withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    public boolean equals(Object o)
    {
        if (o instanceof ECPrivateKey)
        {
            ECPrivateKey other = (ECPrivateKey)o;

            PrivateKeyInfo info = this.getPrivateKeyInfo();
            PrivateKeyInfo otherInfo = (other instanceof BCECPrivateKey) ? ((BCECPrivateKey)other).getPrivateKeyInfo() : PrivateKeyInfo.getInstance(other.getEncoded());

            if (info == null || otherInfo == null)
            {
                return false;
            }

            try
            {
                boolean algEquals = Arrays.constantTimeAreEqual(info.getPrivateKeyAlgorithm().getEncoded(), otherInfo.getPrivateKeyAlgorithm().getEncoded());
                boolean keyEquals = Arrays.constantTimeAreEqual(this.getS().toByteArray(), other.getS().toByteArray());

                return algEquals & keyEquals;
            }
            catch (IOException e)
            {
                return false;
            }
        }

        return false;
    }

    public int hashCode()
    {
        return getD().hashCode() ^ engineGetSpec().hashCode();
    }

    public String toString()
    {
        return ECUtil.privateKeyToString("EC", d, engineGetSpec());
    }

    private ASN1BitString getPublicKeyDetails(BCECPublicKey pub)
    {
        try
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded()));

            return info.getPublicKeyData();
        }
        catch (IOException e)
        {   // should never happen
            return null;
        }
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        this.configuration = CainJCEProvider.CONFIGURATION;

        populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }

    private static ECPrivateKeyParameters convertToBaseKey(BCECPrivateKey key)
    {
        com.github.wegoo.cain.jce.interfaces.ECPrivateKey k = (com.github.wegoo.cain.jce.interfaces.ECPrivateKey)key;
        com.github.wegoo.cain.jce.spec.ECParameterSpec s = k.getParameters();

        if (s == null)
        {
            s = CainJCEProvider.CONFIGURATION.getEcImplicitlyCa();
        }

        if (k.getParameters() instanceof ECNamedCurveParameterSpec)
        {
            String name = ((ECNamedCurveParameterSpec)k.getParameters()).getName();
            if (name != null)
            {
                return new ECPrivateKeyParameters(
                    k.getD(),
                    new ECNamedDomainParameters(ECNamedCurveTable.getOID(name),
                        s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
            }
        }

        return new ECPrivateKeyParameters(
                k.getD(),
                new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
    }
}
