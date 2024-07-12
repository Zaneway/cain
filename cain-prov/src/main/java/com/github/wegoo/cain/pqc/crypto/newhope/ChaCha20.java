package com.github.wegoo.cain.pqc.crypto.newhope;

import com.github.wegoo.cain.crypto.engines.ChaChaEngine;
import com.github.wegoo.cain.crypto.params.KeyParameter;
import com.github.wegoo.cain.crypto.params.ParametersWithIV;

class ChaCha20
{
    static void process(byte[] key, byte[] nonce, byte[] buf, int off, int len)
    {
        ChaChaEngine e = new ChaChaEngine(20);
        e.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        e.processBytes(buf, off, len, buf, off);
    }
}
