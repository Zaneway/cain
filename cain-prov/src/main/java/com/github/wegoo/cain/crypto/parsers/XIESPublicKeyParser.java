package com.github.wegoo.cain.crypto.parsers;

import java.io.IOException;
import java.io.InputStream;

import com.github.wegoo.cain.crypto.KeyParser;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.crypto.params.X25519PublicKeyParameters;
import com.github.wegoo.cain.crypto.params.X448PublicKeyParameters;
import com.github.wegoo.cain.util.io.Streams;

public class XIESPublicKeyParser
    implements KeyParser
{
    private final boolean isX25519;

    public XIESPublicKeyParser(boolean isX25519)
    {
        this.isX25519 = isX25519;
    }

    public AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException
    {
        int size = isX25519 ? 32 : 56;
        byte[] V = new byte[size];
        
        Streams.readFully(stream, V, 0, V.length);

        // cast due to JVM compatibility
        return isX25519 ? (AsymmetricKeyParameter)new X25519PublicKeyParameters(V, 0) : (AsymmetricKeyParameter)new X448PublicKeyParameters(V, 0);
    }
}
