package com.github.wegoo.cain.jce.interfaces;

import java.security.PublicKey;

import com.github.wegoo.cain.math.ec.ECPoint;

/**
 * interface for elliptic curve public keys.
 */
public interface ECPublicKey
    extends ECKey, PublicKey
{
    /**
     * return the public point Q
     */
    public ECPoint getQ();
}
