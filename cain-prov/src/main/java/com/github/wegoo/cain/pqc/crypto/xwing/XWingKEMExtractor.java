package com.github.wegoo.cain.pqc.crypto.xwing;

import com.github.wegoo.cain.crypto.EncapsulatedSecretExtractor;
import com.github.wegoo.cain.crypto.agreement.X25519Agreement;
import com.github.wegoo.cain.crypto.digests.SHA3Digest;
import com.github.wegoo.cain.crypto.params.X25519PrivateKeyParameters;
import com.github.wegoo.cain.crypto.params.X25519PublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import com.github.wegoo.cain.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Strings;

public class XWingKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final XWingPrivateKeyParameters key;
    private final KyberKEMExtractor kemExtractor;

    public XWingKEMExtractor(XWingPrivateKeyParameters privParams)
    {
        this.key = privParams;
        this.kemExtractor = new KyberKEMExtractor((KyberPrivateKeyParameters)key.getKyberPrivateKey());
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        // Decryption
        byte[] kybSecret = kemExtractor.extractSecret(Arrays.copyOfRange(encapsulation, 0, encapsulation.length - X25519PublicKeyParameters.KEY_SIZE));
        X25519Agreement xdhAgree = new X25519Agreement();

        byte[] k = new byte[kybSecret.length + xdhAgree.getAgreementSize()];

        System.arraycopy(kybSecret, 0, k, 0, kybSecret.length);

        Arrays.clear(kybSecret);
        
        xdhAgree.init(key.getXDHPrivateKey());

        X25519PublicKeyParameters ephXdhPub = new X25519PublicKeyParameters(Arrays.copyOfRange(encapsulation, encapsulation.length - X25519PublicKeyParameters.KEY_SIZE, encapsulation.length));

        xdhAgree.calculateAgreement(ephXdhPub, k, kybSecret.length);
        
        SHA3Digest sha3 = new SHA3Digest(256);

        sha3.update(Strings.toByteArray("\\.//^\\"), 0, 6);
        sha3.update(k, 0, k.length);
        sha3.update(ephXdhPub.getEncoded(), 0, X25519PublicKeyParameters.KEY_SIZE);
        sha3.update(((X25519PrivateKeyParameters)key.getXDHPrivateKey()).generatePublicKey().getEncoded(), 0, X25519PublicKeyParameters.KEY_SIZE);

        byte[] kemSecret = new byte[32];

        sha3.doFinal(kemSecret, 0);

        return kemSecret;
    }

    public int getEncapsulationLength()
    {
        return kemExtractor.getEncapsulationLength() + X25519PublicKeyParameters.KEY_SIZE;
    }
}
