package com.github.wegoo.cain.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.CryptoServicePurpose;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.crypto.DerivationFunction;
import com.github.wegoo.cain.crypto.EncapsulatedSecretGenerator;
import com.github.wegoo.cain.crypto.SecretWithEncapsulation;
import com.github.wegoo.cain.crypto.constraints.ConstraintUtils;
import com.github.wegoo.cain.crypto.constraints.DefaultServiceProperties;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.crypto.params.ECDomainParameters;
import com.github.wegoo.cain.crypto.params.ECKeyParameters;
import com.github.wegoo.cain.crypto.params.ECPublicKeyParameters;
import com.github.wegoo.cain.crypto.params.KDFParameters;
import com.github.wegoo.cain.math.ec.ECCurve;
import com.github.wegoo.cain.math.ec.ECMultiplier;
import com.github.wegoo.cain.math.ec.ECPoint;
import com.github.wegoo.cain.math.ec.FixedPointCombMultiplier;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.BigIntegers;

/**
 * The ECIES Key Encapsulation Mechanism (ECIES-KEM) from ISO 18033-2.
 */
public class ECIESKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private DerivationFunction kdf;
    private SecureRandom rnd;
    private final int keySize;
    private boolean CofactorMode;
    private boolean OldCofactorMode;
    private boolean SingleHashMode;

    /**
     * Set up the ECIES-KEM.
     *
     * @param keySize size of the key to be generated (in bytes).
     * @param kdf the key derivation function to be used.
     * @param rnd the random source for the session key.
     */
    public ECIESKEMGenerator(
        int     keySize,
        DerivationFunction kdf,
        SecureRandom rnd)
    {
        this.keySize = keySize;
        this.kdf = kdf;
        this.rnd = rnd;
        this.CofactorMode = false;
        this.OldCofactorMode = false;
        this.SingleHashMode = false;
    }

    /**
     * Set up the ECIES-KEM.
     * @param keyLen          length in bytes of key to generate
     * @param kdf             the key derivation function to be used.
     * @param rnd             the random source for the session key.
     * @param cofactorMode    if true use the new cofactor ECDH.
     * @param oldCofactorMode if true use the old cofactor ECDH.
     * @param singleHashMode  if true use single hash mode.
     */
    public ECIESKEMGenerator(
        int keyLen,
        DerivationFunction kdf,
        SecureRandom rnd,
        boolean cofactorMode,
        boolean oldCofactorMode,
        boolean singleHashMode)
    {
        this.kdf = kdf;
        this.rnd = rnd;
        this.keySize = keyLen;

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
    }

    private ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        if (!(recipientKey instanceof ECKeyParameters))
        {
            throw new IllegalArgumentException("EC key required");
        }

        ECPublicKeyParameters ecPubKey = (ECPublicKeyParameters)recipientKey;

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("ECIESKem",
            ConstraintUtils.bitsOfSecurityFor(ecPubKey.getParameters().getCurve()), recipientKey, CryptoServicePurpose.ENCRYPTION));

        ECDomainParameters ecParams = ecPubKey.getParameters();
        ECCurve curve = ecParams.getCurve();
        BigInteger n = ecParams.getN();
        BigInteger h = ecParams.getH();

        // Generate the ephemeral key pair
        BigInteger r = BigIntegers.createRandomInRange(ONE, n, rnd);

        // Compute the static-ephemeral key agreement
        BigInteger rPrime = OldCofactorMode ? r.multiply(h).mod(n) : r;

        ECMultiplier basePointMultiplier = createBasePointMultiplier();

        ECPoint[] ghTilde = new ECPoint[]{
            basePointMultiplier.multiply(ecParams.getG(), r),
            ecPubKey.getQ().multiply(rPrime)
        };

        // NOTE: More efficient than normalizing each individually
        curve.normalizeAll(ghTilde);

        ECPoint gTilde = ghTilde[0], hTilde = ghTilde[1];

        // Encode the ephemeral public key
        byte[] C = gTilde.getEncoded(false);
        byte[] enc = new byte[C.length];
        System.arraycopy(C, 0, enc, 0, C.length);

        // Encode the shared secret value
        byte[] PEH = hTilde.getAffineXCoord().getEncoded();

        return new SecretWithEncapsulationImpl(deriveKey(SingleHashMode, kdf, this.keySize, C, PEH), enc);
    }

    static byte[] deriveKey(boolean SingleHashMode, DerivationFunction kdf, int keyLen, byte[] C, byte[] PEH)
    {
        byte[] kdfInput = PEH;
        if (!SingleHashMode)
        {
            kdfInput = Arrays.concatenate(C, PEH);
            Arrays.fill(PEH, (byte)0);
        }

        try
        {
            // Initialise the KDF
            kdf.init(new KDFParameters(kdfInput, null));

            // Generate the secret key
            byte[] K = new byte[keyLen];
            kdf.generateBytes(K, 0, K.length);

            // Return the ciphertext
            return K;
        }
        finally
        {
            Arrays.fill(kdfInput, (byte)0);
        }
    }
}
