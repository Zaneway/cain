package com.github.wegoo.cain.its;

import java.util.HashMap;
import java.util.Map;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.nist.NISTObjectIdentifiers;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.HashAlgorithm;

public class ITSAlgorithmUtils
{
    private static final Map<Object, HashAlgorithm> algoMap = new HashMap<Object, HashAlgorithm>();


    static
    {
        algoMap.put(NISTObjectIdentifiers.id_sha256, HashAlgorithm.sha256);
        algoMap.put(NISTObjectIdentifiers.id_sha384, HashAlgorithm.sha384);
    }

    public static HashAlgorithm getHashAlgorithm(ASN1ObjectIdentifier oid)
    {
        return algoMap.get(oid);
    }
}
