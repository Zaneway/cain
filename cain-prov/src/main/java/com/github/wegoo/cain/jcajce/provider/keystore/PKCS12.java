package com.github.wegoo.cain.jcajce.provider.keystore;

import com.github.wegoo.cain.jcajce.provider.config.ConfigurableProvider;
import com.github.wegoo.cain.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.github.wegoo.cain.util.Properties;

public class PKCS12
{
    private static final String PREFIX = "com.github.wegoo.cain.jcajce.provider.keystore" + ".pkcs12.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }
        
        public void configure(ConfigurableProvider provider)
        {
            String defType = Properties.getPropertyValue("com.github.wegoo.cain.pkcs12.default");

            if (defType != null)
            {
                provider.addAlgorithm("Alg.Alias.KeyStore.PKCS12", defType);
                provider.addAlgorithm("Alg.Alias.KeyStore.BCPKCS12", defType);
                provider.addAlgorithm("Alg.Alias.KeyStore.PKCS12-DEF", defType.substring(0, 5) + "-DEF" + defType.substring(6));
            }
            else
            {
                provider.addAlgorithm("KeyStore.PKCS12", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore");
                provider.addAlgorithm("KeyStore.BCPKCS12", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore");
                provider.addAlgorithm("KeyStore.PKCS12-DEF", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore");
            }

            provider.addAlgorithm("KeyStore.PKCS12-3DES-40RC2", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore");
            provider.addAlgorithm("KeyStore.PKCS12-3DES-3DES", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore3DES");
            provider.addAlgorithm("KeyStore.PKCS12-AES256-AES128", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStoreAES256");
            provider.addAlgorithm("KeyStore.PKCS12-AES256-AES128-GCM", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStoreAES256GCM");

            provider.addAlgorithm("KeyStore.PKCS12-DEF-3DES-40RC2", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore");
            provider.addAlgorithm("KeyStore.PKCS12-DEF-3DES-3DES", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore3DES");
            provider.addAlgorithm("KeyStore.PKCS12-DEF-AES256-AES128", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStoreAES256");
            provider.addAlgorithm("KeyStore.PKCS12-DEF-AES256-AES128-GCM", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStoreAES256GCM");
        }
    }
}
