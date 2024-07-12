package com.github.wegoo.cain.crypto.hpke;

import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.crypto.InvalidCipherTextException;
import com.github.wegoo.cain.crypto.engines.AESEngine;
import com.github.wegoo.cain.crypto.modes.AEADCipher;
import com.github.wegoo.cain.crypto.modes.ChaCha20Poly1305;
import com.github.wegoo.cain.crypto.modes.GCMBlockCipher;
import com.github.wegoo.cain.crypto.params.KeyParameter;
import com.github.wegoo.cain.crypto.params.ParametersWithIV;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Pack;

public class AEAD
{

    private final short aeadId;
    private final byte[] key;
    private final byte[] baseNonce;
    private long seq = 0; // todo throw exception if overflow

    private AEADCipher cipher;

    public AEAD(short aeadId, byte[] key, byte[] baseNonce)
    {
        this.key = key;
        this.baseNonce = baseNonce;
        this.aeadId = aeadId;
        seq = 0;

        switch (aeadId)
        {
        case HPKE.aead_AES_GCM128:
        case HPKE.aead_AES_GCM256:
            cipher = new GCMBlockCipher(new AESEngine());
            break;
        case HPKE.aead_CHACHA20_POLY1305:
            cipher = new ChaCha20Poly1305();
            break;
        case HPKE.aead_EXPORT_ONLY:
            break;
        }
    }


    // used by Sender
    public byte[] seal(byte[] aad, byte[] pt, int ptOffset, int ptLength)
        throws InvalidCipherTextException
    {
        if (ptOffset < 0 || ptOffset > pt.length)
        {
            throw new IndexOutOfBoundsException("Invalid offset");
        }
        if (ptOffset + ptLength > pt.length)
        {
            throw new IndexOutOfBoundsException("Invalid length");
        }

        CipherParameters params;
        switch (aeadId)
        {
        case HPKE.aead_AES_GCM128:
        case HPKE.aead_AES_GCM256:
        case HPKE.aead_CHACHA20_POLY1305:
            params = new ParametersWithIV(new KeyParameter(key), ComputeNonce());
            break;
        case HPKE.aead_EXPORT_ONLY:
        default:
            throw new IllegalStateException("Export only mode, cannot be used to seal/open");
        }
        cipher.init(true, params);
        cipher.processAADBytes(aad, 0, aad.length);
        byte[] ct = new byte[cipher.getOutputSize(ptLength)];
        int len = cipher.processBytes(pt, ptOffset, ptLength, ct, 0);
        cipher.doFinal(ct, len);

        seq++;
        return ct;
    }

    // used by Sender
    public byte[] seal(byte[] aad, byte[] pt)
        throws InvalidCipherTextException
    {
        return this.seal(aad, pt, 0, pt.length);
    }

    // used by Receiver
    public byte[] open(byte[] aad, byte[] ct, int ctOffset, int ctLength)
        throws InvalidCipherTextException
    {
        if (ctOffset < 0 || ctOffset > ct.length)
        {
            throw new IndexOutOfBoundsException("Invalid offset");
        }
        if (ctOffset + ctLength > ct.length)
        {
            throw new IndexOutOfBoundsException("Invalid length");
        }

        CipherParameters params;
        switch (aeadId)
        {
        case HPKE.aead_AES_GCM128:
        case HPKE.aead_AES_GCM256:
        case HPKE.aead_CHACHA20_POLY1305:
            params = new ParametersWithIV(new KeyParameter(key), ComputeNonce());
            break;
        case HPKE.aead_EXPORT_ONLY:
        default:
            throw new IllegalStateException("Export only mode, cannot be used to seal/open");
        }

        cipher.init(false, params);
        cipher.processAADBytes(aad, 0, aad.length);

        byte[] pt = new byte[cipher.getOutputSize(ctLength)];
        int len = cipher.processBytes(ct, ctOffset, ctLength, pt, 0);
        len += cipher.doFinal(pt, len);

        seq++;
        return pt;
    }

    // used by Receiver
    public byte[] open(byte[] aad, byte[] ct)
        throws InvalidCipherTextException
    {
        return this.open(aad, ct, 0, ct.length);
    }

    private byte[] ComputeNonce()
    {
        byte[] seq_bytes = Pack.longToBigEndian(seq);
        int Nn = baseNonce.length;
        byte[] nonce = Arrays.clone(baseNonce);
        //xor
        for (int i = 0; i < 8; i++)
        {
            nonce[Nn - 8 + i] ^= seq_bytes[i];
        }
        return nonce;
    }


}

