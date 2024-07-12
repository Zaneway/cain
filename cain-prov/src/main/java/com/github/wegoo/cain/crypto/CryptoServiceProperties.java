package com.github.wegoo.cain.crypto;

public interface CryptoServiceProperties
{
    int bitsOfSecurity();

    String getServiceName();

    CryptoServicePurpose getPurpose();

    Object getParams();
}
