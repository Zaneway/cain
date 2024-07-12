package com.github.wegoo.cain.pqc.jcajce.interfaces;

import java.security.Key;

import com.github.wegoo.cain.pqc.jcajce.spec.KyberParameterSpec;

public interface KyberKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a KyberParameterSpec
     */
    KyberParameterSpec getParameterSpec();
}
