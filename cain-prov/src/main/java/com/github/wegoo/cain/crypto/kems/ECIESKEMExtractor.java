package com.github.wegoo.cain.crypto.kems;

import java.math.BigInteger;

import com.github.wegoo.cain.crypto.CryptoServicePurpose;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.crypto.DerivationFunction;
import com.github.wegoo.cain.crypto.EncapsulatedSecretExtractor;
import com.github.wegoo.cain.crypto.constraints.ConstraintUtils;
import com.github.wegoo.cain.crypto.constraints.DefaultServiceProperties;
import com.github.wegoo.cain.crypto.params.ECDomainParameters;
import com.github.wegoo.cain.crypto.params.ECPrivateKeyParameters;
import com.github.wegoo.cain.math.ec.ECCurve;
import com.github.wegoo.cain.math.ec.ECPoint;

/**
 * The ECIES Key Encapsulation Mechanism (ECIES-KEM) from ISO 18033-2.
 */
public class ECIESKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final ECPrivateKeyParameters decKey;
    private int keyLen;
    private DerivationFunction kdf;

    private boolean CofactorMode;
    private boolean OldCofactorMode;
    private boolean SingleHashMode;

    /**
     * Set up the ECIES-KEM.
     *
     * @param decKey the decryption key.
     * @param keyLen length in bytes of key to generate.
     * @param kdf the key derivation function to be used.
     */
    public ECIESKEMExtractor(
        ECPrivateKeyParameters decKey,
        int keyLen,
        DerivationFunction kdf)
    {
        this.decKey = decKey;
        this.keyLen = keyLen;
        this.kdf = kdf;
        this.CofactorMode = false;
        this.OldCofactorMode = false;
        this.SingleHashMode = false;
    }

    /**
     * Set up the ECIES-KEM.
     *
     * @param decKey          the decryption key.
     * @param keyLen          length in bytes of key to generate.
     * @param kdf             the key derivation function to be used.
     * @param cofactorMode    if true use the new cofactor ECDH.
     * @param oldCofactorMode if true use the old cofactor ECDH.
     * @param singleHashMode  if true use single hash mode.
     */
    public ECIESKEMExtractor(
        ECPrivateKeyParameters decKey,
        int keyLen,
        DerivationFunction kdf,
        boolean cofactorMode,
        boolean oldCofactorMode,
        boolean singleHashMode)
    {
        this.decKey = decKey;
        this.keyLen = keyLen;
        this.kdf = kdf;

        // If both cofactorMode and oldCofactorMode are set to true
        // then the implementation will use the new cofactor ECDH 
        this.CofactorMode = cofactorMode;
        // https://www.shoup.net/iso/std4.pdf, Page 34.
        if (cofactorMode)
        {
            this.OldCofactorMode = false;
        }
        else
        {
            this.OldCofactorMode = oldCofactorMode;
        }
        this.SingleHashMode = singleHashMode;

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("ECIESKem",
            ConstraintUtils.bitsOfSecurityFor(this.decKey.getParameters().getCurve()), decKey, CryptoServicePurpose.DECRYPTION));
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        ECPrivateKeyParameters ecPrivKey = this.decKey;
        ECDomainParameters ecParams = ecPrivKey.getParameters();
        ECCurve curve = ecParams.getCurve();
        BigInteger n = ecParams.getN();
        BigInteger h = ecParams.getH();

        // Decode the ephemeral public key
        // Compute the static-ephemeral key agreement
        ECPoint gHat = curve.decodePoint(encapsulation);
        if ((CofactorMode) || (OldCofactorMode))
        {
            gHat = gHat.multiply(h);
        }

        BigInteger xHat = ecPrivKey.getD();
        if (CofactorMode)
        {
            xHat = xHat.multiply(ecParams.getHInv()).mod(n);
        }

        ECPoint hTilde = gHat.multiply(xHat).normalize();

        // Encode the shared secret value
        byte[] PEH = hTilde.getAffineXCoord().getEncoded();

        return ECIESKEMGenerator.deriveKey(SingleHashMode, kdf, keyLen, encapsulation, PEH);
    }

    public int getEncapsulationLength()
    {
        return (decKey.getParameters().getCurve().getFieldSize() / 8) * 2 + 1;
    }
}
