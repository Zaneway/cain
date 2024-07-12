package com.github.wegoo.cain.pqc.crypto.ntru;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.EncapsulatedSecretGenerator;
import com.github.wegoo.cain.crypto.SecretWithEncapsulation;
import com.github.wegoo.cain.crypto.digests.SHA3Digest;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.pqc.crypto.util.SecretWithEncapsulationImpl;
import com.github.wegoo.cain.pqc.math.ntru.Polynomial;
import com.github.wegoo.cain.pqc.math.ntru.parameters.NTRUParameterSet;
import com.github.wegoo.cain.util.Arrays;

/**
 * Encapsulate a secret using NTRU. returns a {@link SecretWithEncapsulation} as encapsulation.
 *
 * @see NTRUKEMExtractor
 * @see <a href="https://ntru.org/">NTRU website</a>
 */
public class NTRUKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom random;

    /**
     * Constructor
     *
     * @param random a secure random number generator
     */
    public NTRUKEMGenerator(SecureRandom random)
    {
        this.random = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        NTRUParameterSet parameterSet = ((NTRUPublicKeyParameters)recipientKey).getParameters().parameterSet;
        NTRUSampling sampling = new NTRUSampling(parameterSet);
        NTRUOWCPA owcpa = new NTRUOWCPA(parameterSet);
        Polynomial r;
        Polynomial m;
        byte[] rm = new byte[parameterSet.owcpaMsgBytes()];
        byte[] rmSeed = new byte[parameterSet.sampleRmBytes()];

        random.nextBytes(rmSeed);

        PolynomialPair pair = sampling.sampleRm(rmSeed);
        r = pair.r();
        m = pair.m();

        byte[] rm1 = r.s3ToBytes(parameterSet.owcpaMsgBytes());
        System.arraycopy(rm1, 0, rm, 0, rm1.length);
        byte[] rm2 = m.s3ToBytes(rm.length - parameterSet.packTrinaryBytes());
        System.arraycopy(rm2, 0, rm, parameterSet.packTrinaryBytes(), rm2.length);

        SHA3Digest sha3256 = new SHA3Digest(256);
        sha3256.update(rm, 0, rm.length);

        byte[] k = new byte[sha3256.getDigestSize()];

        sha3256.doFinal(k, 0);

        r.z3ToZq();
        byte[] c = owcpa.encrypt(r, m, ((NTRUPublicKeyParameters)recipientKey).publicKey);

        byte[] sharedKey = Arrays.copyOfRange(k, 0, parameterSet.sharedKeyBytes());

        Arrays.clear(k);
        
        return new SecretWithEncapsulationImpl(sharedKey, c);
    }
}
