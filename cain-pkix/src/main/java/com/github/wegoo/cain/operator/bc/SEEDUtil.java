package com.github.wegoo.cain.operator.bc;

import com.github.wegoo.cain.asn1.kisa.KISAObjectIdentifiers;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;

class SEEDUtil
{
    static AlgorithmIdentifier determineKeyEncAlg()
    {
        // parameters absent
        return new AlgorithmIdentifier(
            KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap);
    }
}
