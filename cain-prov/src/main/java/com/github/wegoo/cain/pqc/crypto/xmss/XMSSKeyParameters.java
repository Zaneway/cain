package com.github.wegoo.cain.pqc.crypto.xmss;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public class XMSSKeyParameters
    extends AsymmetricKeyParameter
{
    public static final String SHA_256 = "SHA-256";
    public static final String SHA_512 = "SHA-512";
    public static final String SHAKE128 = "SHAKE128";
    public static final String SHAKE256 = "SHAKE256";

    private final String treeDigest;

    public XMSSKeyParameters(boolean isPrivateKey, String treeDigest)
    {
        super(isPrivateKey);
        this.treeDigest = treeDigest;
    }

    public String getTreeDigest()
    {
        return treeDigest;
    }
}
