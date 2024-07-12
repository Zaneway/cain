package com.github.wegoo.cain.jce.interfaces;

import java.math.BigInteger;

import javax.crypto.interfaces.DHPrivateKey;

public interface ElGamalPrivateKey
    extends ElGamalKey, DHPrivateKey
{
    public BigInteger getX();
}
