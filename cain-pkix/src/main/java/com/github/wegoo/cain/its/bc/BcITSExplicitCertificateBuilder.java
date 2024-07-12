package com.github.wegoo.cain.its.bc;

import com.github.wegoo.cain.crypto.params.ECPublicKeyParameters;
import com.github.wegoo.cain.its.ITSCertificate;
import com.github.wegoo.cain.its.ITSExplicitCertificateBuilder;
import com.github.wegoo.cain.its.ITSPublicEncryptionKey;
import com.github.wegoo.cain.its.operator.ITSContentSigner;
import com.github.wegoo.cain.oer.its.ieee1609dot2.CertificateId;
import com.github.wegoo.cain.oer.its.ieee1609dot2.ToBeSignedCertificate;

public class BcITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder
{
    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    public BcITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(signer, tbsCertificate);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKeyParameters verificationKey)
    {

        return build(certificateId, verificationKey, null);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKeyParameters verificationKey,
        ECPublicKeyParameters encryptionKey)
    {
        ITSPublicEncryptionKey publicEncryptionKey = null;
        if (encryptionKey != null)
        {
            publicEncryptionKey = new BcITSPublicEncryptionKey(encryptionKey);
        }

        return super.build(certificateId, new BcITSPublicVerificationKey(verificationKey), publicEncryptionKey);
    }
}
