package com.github.wegoo.cain.pqc.crypto.falcon;

import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.crypto.params.ParametersWithRandom;
import com.github.wegoo.cain.pqc.crypto.MessageSigner;
import com.github.wegoo.cain.util.encoders.Hex;

public class FalconSigner
    implements MessageSigner
{
    private byte[] encodedkey;
    private FalconNIST nist;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                FalconPrivateKeyParameters skparam = ((FalconPrivateKeyParameters)((ParametersWithRandom)param).getParameters());
                encodedkey = skparam.getEncoded();
                nist = new FalconNIST(skparam.getParameters().getLogN(),
                    skparam.getParameters().getNonceLength(),
                    ((ParametersWithRandom)param).getRandom());
            }
            else
            {
                FalconPrivateKeyParameters skparam = (FalconPrivateKeyParameters)param;
                encodedkey = ((FalconPrivateKeyParameters)param).getEncoded();
                nist = new FalconNIST(skparam.getParameters().getLogN(),
                    skparam.getParameters().getNonceLength(),
                    CryptoServicesRegistrar.getSecureRandom());
            }
        }
        else
        {
            FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)param;
            encodedkey = pkparam.getH();
            nist = new FalconNIST(pkparam.getParameters().getLogN(),
                pkparam.getParameters().getNonceLength(),
                CryptoServicesRegistrar.getSecureRandom());
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        byte[] sm = new byte[nist.CRYPTO_BYTES];

        return nist.crypto_sign(false, sm, message, 0, message.length, encodedkey, 0);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        if (signature[0] != (byte)(0x30 + nist.LOGN))
        {
            return false;
        }
        byte[] nonce = new byte[nist.NONCELEN];
        byte[] sig = new byte[signature.length - nist.NONCELEN - 1];
        System.arraycopy(signature, 1, nonce, 0, nist.NONCELEN);
        System.arraycopy(signature, nist.NONCELEN + 1, sig, 0, signature.length - nist.NONCELEN - 1);
        boolean res = nist.crypto_sign_open(false, sig,nonce,message,encodedkey,0) == 0;
        return res;
    }
}
