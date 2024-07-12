package com.github.wegoo.cain.its.bc;

import java.io.IOException;
import java.io.OutputStream;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.nist.NISTObjectIdentifiers;
import com.github.wegoo.cain.asn1.sec.SECObjectIdentifiers;
import com.github.wegoo.cain.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.crypto.Digest;
import com.github.wegoo.cain.crypto.io.DigestOutputStream;
import com.github.wegoo.cain.crypto.params.ECNamedDomainParameters;
import com.github.wegoo.cain.crypto.params.ECPrivateKeyParameters;
import com.github.wegoo.cain.crypto.signers.DSADigestSigner;
import com.github.wegoo.cain.crypto.signers.ECDSASigner;
import com.github.wegoo.cain.its.ITSCertificate;
import com.github.wegoo.cain.its.operator.ITSContentSigner;
import com.github.wegoo.cain.operator.OperatorCreationException;
import com.github.wegoo.cain.operator.bc.BcDefaultDigestProvider;
import com.github.wegoo.cain.util.Arrays;

public class BcITSContentSigner
    implements ITSContentSigner
{
    private final ECPrivateKeyParameters privKey;
    private final ITSCertificate signerCert;
    private final AlgorithmIdentifier digestAlgo;
    private final Digest digest;
    private final byte[] parentData;
    private final ASN1ObjectIdentifier curveID;
    private final byte[] parentDigest;

    /**
     * Constructor for self-signing.
     *
     * @param privKey
     */
    public BcITSContentSigner(ECPrivateKeyParameters privKey)
    {
        this(privKey, null);
    }

    public BcITSContentSigner(ECPrivateKeyParameters privKey, ITSCertificate signerCert)
    {
        this.privKey = privKey;
        this.curveID = ((ECNamedDomainParameters)privKey.getParameters()).getName();
        this.signerCert = signerCert;
        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
        }
        else
        {
            throw new IllegalArgumentException("unknown key type");
        }

        try
        {
            this.digest = BcDefaultDigestProvider.INSTANCE.get(digestAlgo);
        }
        catch (OperatorCreationException e)
        {
            throw new IllegalStateException("cannot recognise digest type: " + digestAlgo.getAlgorithm());
        }

        if (signerCert != null)
        {
            try
            {
                this.parentData = signerCert.getEncoded();
                this.parentDigest = new byte[digest.getDigestSize()];

                digest.update(parentData, 0, parentData.length);

                digest.doFinal(parentDigest, 0);
            }
            catch (IOException e)
            {
                throw new IllegalStateException("signer certificate encoding failed: " + e.getMessage());
            }
        }
        else
        {
            // self signed so we use a null digest for the parent.
            this.parentData = null;
            this.parentDigest = new byte[digest.getDigestSize()];
            digest.doFinal(parentDigest, 0);
        }
    }

    public ITSCertificate getAssociatedCertificate()
    {
        return signerCert;
    }

    public byte[] getAssociatedCertificateDigest()
    {
        return Arrays.clone(parentDigest);
    }

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgo;
    }

    public OutputStream getOutputStream()
    {
        return new DigestOutputStream(digest);
    }

    public boolean isForSelfSigning()
    {
        return parentData == null;
    }

    public ASN1ObjectIdentifier getCurveID()
    {
        return curveID;
    }

    public byte[] getSignature()
    {
        byte[] clientCertDigest = new byte[digest.getDigestSize()];

        digest.doFinal(clientCertDigest, 0);

        final DSADigestSigner signer = new DSADigestSigner(new ECDSASigner(), digest);

        signer.init(true, privKey);

        signer.update(clientCertDigest, 0, clientCertDigest.length);

        signer.update(parentDigest, 0, parentDigest.length);

        return signer.generateSignature();
    }
}
