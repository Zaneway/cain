package com.github.wegoo.cain.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.jcajce.provider.asymmetric.compositesignatures.CompositeSignaturesConstants;
import com.github.wegoo.cain.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import com.github.wegoo.cain.jcajce.provider.config.ConfigurableProvider;
import com.github.wegoo.cain.jcajce.provider.util.AsymmetricAlgorithmProvider;

/**
 * Experimental implementation of composite signatures according to https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-sigs-13.
 */
public class CompositeSignatures
{
    private static final String PREFIX = "com.github.wegoo.cain.jcajce.provider.asymmetric" + ".compositesignatures.";

    private static final Map<String, String> compositesAttributes = new HashMap<String, String>();

    static
    {
        compositesAttributes.put("SupportedKeyClasses", "com.github.wegoo.cain.jcajce.CompositePublicKey|com.github.wegoo.cain.jcajce.CompositePrivateKey");
        compositesAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
            extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            for (ASN1ObjectIdentifier oid : CompositeSignaturesConstants.supportedIdentifiers)
            {
                CompositeSignaturesConstants.CompositeName algName = CompositeSignaturesConstants.ASN1IdentifierAlgorithmNameMap.get(oid);
                provider.addAlgorithm("KeyFactory." + algName.getId(), PREFIX + "KeyFactorySpi"); //Key factory is the same for all composite signatures.
                provider.addAlgorithm("Alg.Alias.KeyFactory", oid, algName.getId());

                provider.addAlgorithm("KeyPairGenerator." + algName.getId(), PREFIX + "KeyPairGeneratorSpi$" + algName);
                provider.addAlgorithm("Alg.Alias.KeyPairGenerator", oid, algName.getId());

                provider.addAlgorithm("Signature." + algName.getId(), PREFIX + "SignatureSpi$" + algName);
                provider.addAlgorithm("Alg.Alias.Signature", oid, algName.getId());

                provider.addKeyInfoConverter(oid, new KeyFactorySpi());
            }
        }
    }
}
